use crate::atomicio::atomicio;
use ::libc;

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
    pub type ssh_digest_ctx;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn arc4random_buf(_: *mut libc::c_void, _: size_t);
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;
    fn memchr(_: *const libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;

    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;
    fn DH_free(dh: *mut DH);

    fn EC_KEY_free(key: *mut EC_KEY);
    fn ssh_dispatch_set(_: *mut ssh, _: libc::c_int, _: Option<dispatch_fn>);
    fn ssh_dispatch_range(_: *mut ssh, _: u_int, _: u_int, _: Option<dispatch_fn>);
    fn ssh_set_newkeys(_: *mut ssh, mode: libc::c_int) -> libc::c_int;
    fn ssh_remote_ipaddr(_: *mut ssh) -> *const libc::c_char;
    fn ssh_remote_port(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_get_connection_in(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_get_connection_out(_: *mut ssh) -> libc::c_int;
    fn sshpkt_putb(ssh: *mut ssh, b: *const crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshpkt_put_u32(ssh: *mut ssh, val: u_int32_t) -> libc::c_int;
    fn sshpkt_put_cstring(ssh: *mut ssh, v: *const libc::c_void) -> libc::c_int;
    fn sshpkt_start(ssh: *mut ssh, type_0: u_char) -> libc::c_int;
    fn sshpkt_send(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_get_string(ssh: *mut ssh, valp: *mut *mut u_char, lenp: *mut size_t) -> libc::c_int;
    fn sshpkt_get_u8(ssh: *mut ssh, valp: *mut u_char) -> libc::c_int;
    fn sshpkt_get_u32(ssh: *mut ssh, valp: *mut u_int32_t) -> libc::c_int;
    fn sshpkt_get_cstring(
        ssh: *mut ssh,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshpkt_get_end(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_ptr(_: *mut ssh, lenp: *mut size_t) -> *const u_char;
    fn compat_banner(_: *mut ssh, _: *const libc::c_char);
    fn compat_kex_proposal(_: *mut ssh, _: *const libc::c_char) -> *mut libc::c_char;
    fn cipher_ivlen(_: *const sshcipher) -> u_int;
    fn cipher_authlen(_: *const sshcipher) -> u_int;
    fn cipher_seclen(_: *const sshcipher) -> u_int;
    fn cipher_keylen(_: *const sshcipher) -> u_int;
    fn cipher_blocksize(_: *const sshcipher) -> u_int;
    fn cipher_by_name(_: *const libc::c_char) -> *const sshcipher;
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_type_from_name(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_alg_list(
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_char,
    ) -> *mut libc::c_char;
    fn sshkey_ecdsa_nid_from_name(_: *const libc::c_char) -> libc::c_int;
    fn mac_setup(_: *mut sshmac, _: *mut libc::c_char) -> libc::c_int;
    fn mac_clear(_: *mut sshmac);
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
    fn match_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut u_int,
    ) -> *mut libc::c_char;
    fn match_filter_denylist(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn match_filter_allowlist(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn waitrfd(_: libc::c_int, _: *mut libc::c_int) -> libc::c_int;

    fn sshbuf_fromb(buf: *mut crate::sshbuf::sshbuf) -> *mut crate::sshbuf::sshbuf;

    fn sshbuf_reset(buf: *mut crate::sshbuf::sshbuf);
    fn sshbuf_len(buf: *const crate::sshbuf::sshbuf) -> size_t;
    fn sshbuf_ptr(buf: *const crate::sshbuf::sshbuf) -> *const u_char;
    fn sshbuf_mutable_ptr(buf: *const crate::sshbuf::sshbuf) -> *mut u_char;
    fn sshbuf_consume(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_consume_end(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;

    fn sshbuf_get_u32(buf: *mut crate::sshbuf::sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut crate::sshbuf::sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut crate::sshbuf::sshbuf, val: u_int32_t) -> libc::c_int;

    fn sshbuf_get_cstring(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut crate::sshbuf::sshbuf, v: *const libc::c_char) -> libc::c_int;
    
    fn ssh_digest_bytes(alg: libc::c_int) -> size_t;
    fn ssh_digest_start(alg: libc::c_int) -> *mut ssh_digest_ctx;
    fn ssh_digest_update(
        ctx: *mut ssh_digest_ctx,
        m: *const libc::c_void,
        mlen: size_t,
    ) -> libc::c_int;
    fn ssh_digest_update_buffer(
        ctx: *mut ssh_digest_ctx,
        b: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn ssh_digest_final(ctx: *mut ssh_digest_ctx, d: *mut u_char, dlen: size_t) -> libc::c_int;
    fn ssh_digest_free(ctx: *mut ssh_digest_ctx);

}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __ssize_t = libc::c_long;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type ssize_t = __ssize_t;
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
pub type kex_modes = libc::c_uint;
pub const MODE_MAX: kex_modes = 2;
pub const MODE_OUT: kex_modes = 1;
pub const MODE_IN: kex_modes = 0;
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
pub struct kexalg {
    pub name: *mut libc::c_char,
    pub type_0: u_int,
    pub ec_nid: libc::c_int,
    pub hash_alg: libc::c_int,
}
static mut proposal_names: [*const libc::c_char; 10] = [
    b"KEX algorithms\0" as *const u8 as *const libc::c_char,
    b"host key algorithms\0" as *const u8 as *const libc::c_char,
    b"ciphers ctos\0" as *const u8 as *const libc::c_char,
    b"ciphers stoc\0" as *const u8 as *const libc::c_char,
    b"MACs ctos\0" as *const u8 as *const libc::c_char,
    b"MACs stoc\0" as *const u8 as *const libc::c_char,
    b"compression ctos\0" as *const u8 as *const libc::c_char,
    b"compression stoc\0" as *const u8 as *const libc::c_char,
    b"languages ctos\0" as *const u8 as *const libc::c_char,
    b"languages stoc\0" as *const u8 as *const libc::c_char,
];
static mut kexalgs: [kexalg; 14] = [
    {
        let mut init = kexalg {
            name: b"diffie-hellman-group1-sha1\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: KEX_DH_GRP1_SHA1 as libc::c_int as u_int,
            ec_nid: 0 as libc::c_int,
            hash_alg: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = kexalg {
            name: b"diffie-hellman-group14-sha1\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: KEX_DH_GRP14_SHA1 as libc::c_int as u_int,
            ec_nid: 0 as libc::c_int,
            hash_alg: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = kexalg {
            name: b"diffie-hellman-group14-sha256\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: KEX_DH_GRP14_SHA256 as libc::c_int as u_int,
            ec_nid: 0 as libc::c_int,
            hash_alg: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = kexalg {
            name: b"diffie-hellman-group16-sha512\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: KEX_DH_GRP16_SHA512 as libc::c_int as u_int,
            ec_nid: 0 as libc::c_int,
            hash_alg: 4 as libc::c_int,
        };
        init
    },
    {
        let mut init = kexalg {
            name: b"diffie-hellman-group18-sha512\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: KEX_DH_GRP18_SHA512 as libc::c_int as u_int,
            ec_nid: 0 as libc::c_int,
            hash_alg: 4 as libc::c_int,
        };
        init
    },
    {
        let mut init = kexalg {
            name: b"diffie-hellman-group-exchange-sha1\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: KEX_DH_GEX_SHA1 as libc::c_int as u_int,
            ec_nid: 0 as libc::c_int,
            hash_alg: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = kexalg {
            name: b"diffie-hellman-group-exchange-sha256\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: KEX_DH_GEX_SHA256 as libc::c_int as u_int,
            ec_nid: 0 as libc::c_int,
            hash_alg: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = kexalg {
            name: b"ecdh-sha2-nistp256\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            type_0: KEX_ECDH_SHA2 as libc::c_int as u_int,
            ec_nid: 415 as libc::c_int,
            hash_alg: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = kexalg {
            name: b"ecdh-sha2-nistp384\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            type_0: KEX_ECDH_SHA2 as libc::c_int as u_int,
            ec_nid: 715 as libc::c_int,
            hash_alg: 3 as libc::c_int,
        };
        init
    },
    {
        let mut init = kexalg {
            name: b"ecdh-sha2-nistp521\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            type_0: KEX_ECDH_SHA2 as libc::c_int as u_int,
            ec_nid: 716 as libc::c_int,
            hash_alg: 4 as libc::c_int,
        };
        init
    },
    {
        let mut init = kexalg {
            name: b"curve25519-sha256\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            type_0: KEX_C25519_SHA256 as libc::c_int as u_int,
            ec_nid: 0 as libc::c_int,
            hash_alg: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = kexalg {
            name: b"curve25519-sha256@libssh.org\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: KEX_C25519_SHA256 as libc::c_int as u_int,
            ec_nid: 0 as libc::c_int,
            hash_alg: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = kexalg {
            name: b"sntrup761x25519-sha512@openssh.com\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: KEX_KEM_SNTRUP761X25519_SHA512 as libc::c_int as u_int,
            ec_nid: 0 as libc::c_int,
            hash_alg: 4 as libc::c_int,
        };
        init
    },
    {
        let mut init = kexalg {
            name: 0 as *const libc::c_char as *mut libc::c_char,
            type_0: 0 as libc::c_int as u_int,
            ec_nid: -(1 as libc::c_int),
            hash_alg: -(1 as libc::c_int),
        };
        init
    },
];
pub unsafe extern "C" fn kex_alg_list(mut sep: libc::c_char) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut nlen: size_t = 0;
    let mut rlen: size_t = 0 as libc::c_int as size_t;
    let mut k: *const kexalg = 0 as *const kexalg;
    k = kexalgs.as_ptr();
    while !((*k).name).is_null() {
        if !ret.is_null() {
            let fresh0 = rlen;
            rlen = rlen.wrapping_add(1);
            *ret.offset(fresh0 as isize) = sep;
        }
        nlen = strlen((*k).name);
        tmp = realloc(
            ret as *mut libc::c_void,
            rlen.wrapping_add(nlen)
                .wrapping_add(2 as libc::c_int as libc::c_ulong),
        ) as *mut libc::c_char;
        if tmp.is_null() {
            libc::free(ret as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
        ret = tmp;
        memcpy(
            ret.offset(rlen as isize) as *mut libc::c_void,
            (*k).name as *const libc::c_void,
            nlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
        );
        rlen = (rlen as libc::c_ulong).wrapping_add(nlen) as size_t as size_t;
        k = k.offset(1);
        k;
    }
    return ret;
}
unsafe extern "C" fn kex_alg_by_name(mut name: *const libc::c_char) -> *const kexalg {
    let mut k: *const kexalg = 0 as *const kexalg;
    k = kexalgs.as_ptr();
    while !((*k).name).is_null() {
        if libc::strcmp((*k).name, name) == 0 as libc::c_int {
            return k;
        }
        k = k.offset(1);
        k;
    }
    return 0 as *const kexalg;
}
pub unsafe extern "C" fn kex_names_valid(mut names: *const libc::c_char) -> libc::c_int {
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    if names.is_null()
        || libc::strcmp(names, b"\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    cp = libc::strdup(names);
    s = cp;
    if s.is_null() {
        return 0 as libc::c_int;
    }
    p = strsep(&mut cp, b",\0" as *const u8 as *const libc::c_char);
    while !p.is_null() && *p as libc::c_int != '\0' as i32 {
        if (kex_alg_by_name(p)).is_null() {
            crate::log::sshlog(
                b"kex.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"kex_names_valid\0"))
                    .as_ptr(),
                170 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Unsupported KEX algorithm \"%.100s\"\0" as *const u8 as *const libc::c_char,
                p,
            );
            libc::free(s as *mut libc::c_void);
            return 0 as libc::c_int;
        }
        p = strsep(&mut cp, b",\0" as *const u8 as *const libc::c_char);
    }
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"kex_names_valid\0")).as_ptr(),
        175 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"kex names ok: [%s]\0" as *const u8 as *const libc::c_char,
        names,
    );
    libc::free(s as *mut libc::c_void);
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn kex_names_cat(
    mut a: *const libc::c_char,
    mut b: *const libc::c_char,
) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut m: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: size_t = 0;
    if a.is_null() || *a as libc::c_int == '\0' as i32 {
        return libc::strdup(b);
    }
    if b.is_null() || *b as libc::c_int == '\0' as i32 {
        return libc::strdup(a);
    }
    if strlen(b) > (1024 as libc::c_int * 1024 as libc::c_int) as libc::c_ulong {
        return 0 as *mut libc::c_char;
    }
    len = (strlen(a))
        .wrapping_add(strlen(b))
        .wrapping_add(2 as libc::c_int as libc::c_ulong);
    cp = libc::strdup(b);
    tmp = cp;
    if tmp.is_null() || {
        ret = calloc(1 as libc::c_int as libc::c_ulong, len) as *mut libc::c_char;
        ret.is_null()
    } {
        libc::free(tmp as *mut libc::c_void);
        return 0 as *mut libc::c_char;
    }
    strlcpy(ret, a, len);
    p = strsep(&mut cp, b",\0" as *const u8 as *const libc::c_char);
    while !p.is_null() && *p as libc::c_int != '\0' as i32 {
        m = match_list(ret, p, 0 as *mut u_int);
        if !m.is_null() {
            libc::free(m as *mut libc::c_void);
        } else if strlcat(ret, b",\0" as *const u8 as *const libc::c_char, len) >= len
            || strlcat(ret, p, len) >= len
        {
            libc::free(tmp as *mut libc::c_void);
            libc::free(ret as *mut libc::c_void);
            return 0 as *mut libc::c_char;
        }
        p = strsep(&mut cp, b",\0" as *const u8 as *const libc::c_char);
    }
    libc::free(tmp as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn kex_assemble_names(
    mut listp: *mut *mut libc::c_char,
    mut def: *const libc::c_char,
    mut all: *const libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut patterns: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut list: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut matching: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut opatterns: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = -(1 as libc::c_int);
    if listp.is_null() || def.is_null() || all.is_null() {
        return -(10 as libc::c_int);
    }
    if (*listp).is_null() || **listp as libc::c_int == '\0' as i32 {
        *listp = libc::strdup(def);
        if (*listp).is_null() {
            return -(2 as libc::c_int);
        }
        return 0 as libc::c_int;
    }
    list = *listp;
    *listp = 0 as *mut libc::c_char;
    if *list as libc::c_int == '+' as i32 {
        tmp = kex_names_cat(def, list.offset(1 as libc::c_int as isize));
        if tmp.is_null() {
            r = -(2 as libc::c_int);
            current_block = 7592391467544181933;
        } else {
            libc::free(list as *mut libc::c_void);
            list = tmp;
            current_block = 5783071609795492627;
        }
    } else if *list as libc::c_int == '-' as i32 {
        *listp = match_filter_denylist(def, list.offset(1 as libc::c_int as isize));
        if (*listp).is_null() {
            r = -(2 as libc::c_int);
        } else {
            libc::free(list as *mut libc::c_void);
            return 0 as libc::c_int;
        }
        current_block = 7592391467544181933;
    } else if *list as libc::c_int == '^' as i32 {
        tmp = kex_names_cat(list.offset(1 as libc::c_int as isize), def);
        if tmp.is_null() {
            r = -(2 as libc::c_int);
            current_block = 7592391467544181933;
        } else {
            libc::free(list as *mut libc::c_void);
            list = tmp;
            current_block = 5783071609795492627;
        }
    } else {
        current_block = 5783071609795492627;
    }
    match current_block {
        5783071609795492627 => {
            ret = 0 as *mut libc::c_char;
            opatterns = libc::strdup(list);
            patterns = opatterns;
            if patterns.is_null() {
                r = -(2 as libc::c_int);
            } else {
                loop {
                    cp = strsep(&mut patterns, b",\0" as *const u8 as *const libc::c_char);
                    if cp.is_null() {
                        current_block = 1118134448028020070;
                        break;
                    }
                    if *cp as libc::c_int == '!' as i32 {
                        r = -(10 as libc::c_int);
                        current_block = 7592391467544181933;
                        break;
                    } else {
                        libc::free(matching as *mut libc::c_void);
                        matching = match_filter_allowlist(all, cp);
                        if matching.is_null() {
                            r = -(2 as libc::c_int);
                            current_block = 7592391467544181933;
                            break;
                        } else {
                            tmp = kex_names_cat(ret, matching);
                            if tmp.is_null() {
                                r = -(2 as libc::c_int);
                                current_block = 7592391467544181933;
                                break;
                            } else {
                                libc::free(ret as *mut libc::c_void);
                                ret = tmp;
                            }
                        }
                    }
                }
                match current_block {
                    7592391467544181933 => {}
                    _ => {
                        if ret.is_null() || *ret as libc::c_int == '\0' as i32 {
                            r = -(10 as libc::c_int);
                        } else {
                            *listp = ret;
                            ret = 0 as *mut libc::c_char;
                            r = 0 as libc::c_int;
                        }
                    }
                }
            }
        }
        _ => {}
    }
    libc::free(matching as *mut libc::c_void);
    libc::free(opatterns as *mut libc::c_void);
    libc::free(list as *mut libc::c_void);
    libc::free(ret as *mut libc::c_void);
    return r;
}
pub unsafe extern "C" fn kex_proposal_populate_entries(
    mut ssh: *mut ssh,
    mut prop: *mut *mut libc::c_char,
    mut kexalgos: *const libc::c_char,
    mut ciphers: *const libc::c_char,
    mut macs: *const libc::c_char,
    mut comp: *const libc::c_char,
    mut hkalgs: *const libc::c_char,
) {
    let mut defpropserver: [*const libc::c_char; 10] = [
        b"sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256\0"
            as *const u8 as *const libc::c_char,
        b"ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\0"
            as *const u8 as *const libc::c_char,
        b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\0"
            as *const u8 as *const libc::c_char,
        b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\0"
            as *const u8 as *const libc::c_char,
        b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\0"
            as *const u8 as *const libc::c_char,
        b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\0"
            as *const u8 as *const libc::c_char,
        b"none,zlib@openssh.com\0" as *const u8 as *const libc::c_char,
        b"none,zlib@openssh.com\0" as *const u8 as *const libc::c_char,
        b"\0" as *const u8 as *const libc::c_char,
        b"\0" as *const u8 as *const libc::c_char,
    ];
    let mut defpropclient: [*const libc::c_char; 10] = [
        b"sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256\0"
            as *const u8 as *const libc::c_char,
        b"ssh-ed25519-cert-v01@openssh.com,ecdsa-sha2-nistp256-cert-v01@openssh.com,ecdsa-sha2-nistp384-cert-v01@openssh.com,ecdsa-sha2-nistp521-cert-v01@openssh.com,sk-ssh-ed25519-cert-v01@openssh.com,sk-ecdsa-sha2-nistp256-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com,rsa-sha2-512,rsa-sha2-256\0"
            as *const u8 as *const libc::c_char,
        b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\0"
            as *const u8 as *const libc::c_char,
        b"chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com\0"
            as *const u8 as *const libc::c_char,
        b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\0"
            as *const u8 as *const libc::c_char,
        b"umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1\0"
            as *const u8 as *const libc::c_char,
        b"none,zlib@openssh.com\0" as *const u8 as *const libc::c_char,
        b"none,zlib@openssh.com\0" as *const u8 as *const libc::c_char,
        b"\0" as *const u8 as *const libc::c_char,
        b"\0" as *const u8 as *const libc::c_char,
    ];
    let mut defprop: *mut *const libc::c_char = if (*(*ssh).kex).server != 0 {
        defpropserver.as_mut_ptr()
    } else {
        defpropclient.as_mut_ptr()
    };
    let mut i: u_int = 0;
    if prop.is_null() {
        sshfatal(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"kex_proposal_populate_entries\0",
            ))
            .as_ptr(),
            339 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"proposal missing\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int as u_int;
    while i < PROPOSAL_MAX as libc::c_int as libc::c_uint {
        match i {
            0 => {
                let ref mut fresh1 = *prop.offset(i as isize);
                *fresh1 = compat_kex_proposal(
                    ssh,
                    if !kexalgos.is_null() {
                        kexalgos
                    } else {
                        *defprop.offset(i as isize)
                    },
                );
            }
            2 | 3 => {
                let ref mut fresh2 = *prop.offset(i as isize);
                *fresh2 = crate::xmalloc::xstrdup(if !ciphers.is_null() {
                    ciphers
                } else {
                    *defprop.offset(i as isize)
                });
            }
            4 | 5 => {
                let ref mut fresh3 = *prop.offset(i as isize);
                *fresh3 = crate::xmalloc::xstrdup(if !macs.is_null() {
                    macs
                } else {
                    *defprop.offset(i as isize)
                });
            }
            6 | 7 => {
                let ref mut fresh4 = *prop.offset(i as isize);
                *fresh4 = crate::xmalloc::xstrdup(if !comp.is_null() {
                    comp
                } else {
                    *defprop.offset(i as isize)
                });
            }
            1 => {
                let ref mut fresh5 = *prop.offset(i as isize);
                *fresh5 = crate::xmalloc::xstrdup(if !hkalgs.is_null() {
                    hkalgs
                } else {
                    *defprop.offset(i as isize)
                });
            }
            _ => {
                let ref mut fresh6 = *prop.offset(i as isize);
                *fresh6 = crate::xmalloc::xstrdup(*defprop.offset(i as isize));
            }
        }
        i = i.wrapping_add(1);
        i;
    }
}
pub unsafe extern "C" fn kex_proposal_free_entries(mut prop: *mut *mut libc::c_char) {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < PROPOSAL_MAX as libc::c_int as libc::c_uint {
        libc::free(*prop.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
}
pub unsafe extern "C" fn kex_prop2buf(
    mut b: *mut crate::sshbuf::sshbuf,
    mut proposal: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut i: u_int = 0;
    let mut r: libc::c_int = 0;
    sshbuf_reset(b);
    i = 0 as libc::c_int as u_int;
    while i < 16 as libc::c_int as libc::c_uint {
        r = crate::sshbuf_getput_basic::sshbuf_put_u8(b, 0 as libc::c_int as u_char);
        if r != 0 as libc::c_int {
            return r;
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < PROPOSAL_MAX as libc::c_int as libc::c_uint {
        r = sshbuf_put_cstring(b, *proposal.offset(i as isize));
        if r != 0 as libc::c_int {
            return r;
        }
        i = i.wrapping_add(1);
        i;
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_u8(b, 0 as libc::c_int as u_char);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_u32(b, 0 as libc::c_int as u_int32_t);
        r != 0 as libc::c_int
    } {
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn kex_buf2prop(
    mut raw: *mut crate::sshbuf::sshbuf,
    mut first_kex_follows: *mut libc::c_int,
    mut propp: *mut *mut *mut libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut v: u_char = 0;
    let mut i: u_int = 0;
    let mut proposal: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut r: libc::c_int = 0;
    *propp = 0 as *mut *mut libc::c_char;
    proposal = calloc(
        PROPOSAL_MAX as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    if proposal.is_null() {
        return -(2 as libc::c_int);
    }
    b = sshbuf_fromb(raw);
    if b.is_null() {
        r = -(2 as libc::c_int);
    } else {
        r = sshbuf_consume(b, 16 as libc::c_int as size_t);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"kex.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"kex_buf2prop\0"))
                    .as_ptr(),
                422 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"consume cookie\0" as *const u8 as *const libc::c_char,
            );
        } else {
            i = 0 as libc::c_int as u_int;
            loop {
                if !(i < PROPOSAL_MAX as libc::c_int as libc::c_uint) {
                    current_block = 11050875288958768710;
                    break;
                }
                r = sshbuf_get_cstring(b, &mut *proposal.offset(i as isize), 0 as *mut size_t);
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"kex.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"kex_buf2prop\0",
                        ))
                        .as_ptr(),
                        428 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"parse proposal %u\0" as *const u8 as *const libc::c_char,
                        i,
                    );
                    current_block = 14439343106787185477;
                    break;
                } else {
                    crate::log::sshlog(
                        b"kex.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"kex_buf2prop\0",
                        ))
                        .as_ptr(),
                        431 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        0 as *const libc::c_char,
                        b"%s: %s\0" as *const u8 as *const libc::c_char,
                        proposal_names[i as usize],
                        *proposal.offset(i as isize),
                    );
                    i = i.wrapping_add(1);
                    i;
                }
            }
            match current_block {
                14439343106787185477 => {}
                _ => {
                    r = sshbuf_get_u8(b, &mut v);
                    if r != 0 as libc::c_int || {
                        r = sshbuf_get_u32(b, &mut i);
                        r != 0 as libc::c_int
                    } {
                        crate::log::sshlog(
                            b"kex.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"kex_buf2prop\0",
                            ))
                            .as_ptr(),
                            436 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"parse\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        if !first_kex_follows.is_null() {
                            *first_kex_follows = v as libc::c_int;
                        }
                        crate::log::sshlog(
                            b"kex.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"kex_buf2prop\0",
                            ))
                            .as_ptr(),
                            441 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"first_kex_follows %d \0" as *const u8 as *const libc::c_char,
                            v as libc::c_int,
                        );
                        crate::log::sshlog(
                            b"kex.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"kex_buf2prop\0",
                            ))
                            .as_ptr(),
                            442 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"reserved %u \0" as *const u8 as *const libc::c_char,
                            i,
                        );
                        r = 0 as libc::c_int;
                        *propp = proposal;
                    }
                }
            }
        }
    }
    if r != 0 as libc::c_int && !proposal.is_null() {
        kex_prop_free(proposal);
    }
    crate::sshbuf::sshbuf_free(b);
    return r;
}
pub unsafe extern "C" fn kex_prop_free(mut proposal: *mut *mut libc::c_char) {
    let mut i: u_int = 0;
    if proposal.is_null() {
        return;
    }
    i = 0 as libc::c_int as u_int;
    while i < PROPOSAL_MAX as libc::c_int as libc::c_uint {
        libc::free(*proposal.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free(proposal as *mut libc::c_void);
}
pub unsafe extern "C" fn kex_protocol_error(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"kex_protocol_error\0"))
            .as_ptr(),
        469 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"kex protocol error: type %d seq %u\0" as *const u8 as *const libc::c_char,
        type_0,
        seq,
    );
    r = sshpkt_start(ssh, 3 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_u32(ssh, seq);
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
unsafe extern "C" fn kex_reset_dispatch(mut ssh: *mut ssh) {
    ssh_dispatch_range(
        ssh,
        1 as libc::c_int as u_int,
        49 as libc::c_int as u_int,
        Some(
            kex_protocol_error
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
}
unsafe extern "C" fn kex_send_ext_info(mut ssh: *mut ssh) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut algs: *mut libc::c_char = 0 as *mut libc::c_char;
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"kex_send_ext_info\0"))
            .as_ptr(),
        490 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Sending SSH2_MSG_EXT_INFO\0" as *const u8 as *const libc::c_char,
    );
    algs = sshkey_alg_list(
        0 as libc::c_int,
        1 as libc::c_int,
        1 as libc::c_int,
        ',' as i32 as libc::c_char,
    );
    if algs.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshpkt_start(ssh, 7 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_u32(ssh, 2 as libc::c_int as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_cstring(
                ssh,
                b"server-sig-algs\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_cstring(ssh, algs as *const libc::c_void);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_cstring(
                ssh,
                b"publickey-hostbound@openssh.com\0" as *const u8 as *const libc::c_char
                    as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_cstring(
                ssh,
                b"0\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"kex_send_ext_info\0"))
                .as_ptr(),
            502 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    } else {
        r = 0 as libc::c_int;
    }
    libc::free(algs as *mut libc::c_void);
    return r;
}
pub unsafe extern "C" fn kex_send_newkeys(mut ssh: *mut ssh) -> libc::c_int {
    let mut r: libc::c_int = 0;
    kex_reset_dispatch(ssh);
    r = sshpkt_start(ssh, 21 as libc::c_int as u_char);
    if r != 0 as libc::c_int || {
        r = sshpkt_send(ssh);
        r != 0 as libc::c_int
    } {
        return r;
    }
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"kex_send_newkeys\0")).as_ptr(),
        521 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"SSH2_MSG_NEWKEYS sent\0" as *const u8 as *const libc::c_char,
    );
    ssh_dispatch_set(
        ssh,
        21 as libc::c_int,
        Some(
            kex_input_newkeys
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    if (*(*ssh).kex).ext_info_c != 0
        && (*(*ssh).kex).flags & 0x2 as libc::c_int as libc::c_uint
            != 0 as libc::c_int as libc::c_uint
    {
        r = kex_send_ext_info(ssh);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"kex_send_newkeys\0")).as_ptr(),
        526 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"expecting SSH2_MSG_NEWKEYS\0" as *const u8 as *const libc::c_char,
    );
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn kex_input_ext_info(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    let mut i: u_int32_t = 0;
    let mut ninfo: u_int32_t = 0;
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut val: *mut u_char = 0 as *mut u_char;
    let mut vlen: size_t = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"kex_input_ext_info\0"))
            .as_ptr(),
        540 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"SSH2_MSG_EXT_INFO received\0" as *const u8 as *const libc::c_char,
    );
    ssh_dispatch_set(
        ssh,
        7 as libc::c_int,
        Some(
            kex_protocol_error
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    r = sshpkt_get_u32(ssh, &mut ninfo);
    if r != 0 as libc::c_int {
        return r;
    }
    if ninfo >= 1024 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"kex_input_ext_info\0"))
                .as_ptr(),
            546 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"SSH2_MSG_EXT_INFO with too many entries, expected <=1024, received %u\0" as *const u8
                as *const libc::c_char,
            ninfo,
        );
        return -(4 as libc::c_int);
    }
    i = 0 as libc::c_int as u_int32_t;
    while i < ninfo {
        r = sshpkt_get_cstring(ssh, &mut name, 0 as *mut size_t);
        if r != 0 as libc::c_int {
            return r;
        }
        r = sshpkt_get_string(ssh, &mut val, &mut vlen);
        if r != 0 as libc::c_int {
            libc::free(name as *mut libc::c_void);
            return r;
        }
        if libc::strcmp(
            name,
            b"server-sig-algs\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            if !(memchr(val as *const libc::c_void, '\0' as i32, vlen)).is_null() {
                crate::log::sshlog(
                    b"kex.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"kex_input_ext_info\0",
                    ))
                    .as_ptr(),
                    559 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"nul byte in %s\0" as *const u8 as *const libc::c_char,
                    name,
                );
                return -(4 as libc::c_int);
            }
            crate::log::sshlog(
                b"kex.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"kex_input_ext_info\0",
                ))
                .as_ptr(),
                562 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"%s=<%s>\0" as *const u8 as *const libc::c_char,
                name,
                val,
            );
            (*kex).server_sig_algs = val as *mut libc::c_char;
            val = 0 as *mut u_char;
        } else if libc::strcmp(
            name,
            b"publickey-hostbound@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            if !(memchr(val as *const libc::c_void, '\0' as i32, vlen)).is_null() {
                crate::log::sshlog(
                    b"kex.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"kex_input_ext_info\0",
                    ))
                    .as_ptr(),
                    570 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"nul byte in %s\0" as *const u8 as *const libc::c_char,
                    name,
                );
                return -(4 as libc::c_int);
            }
            crate::log::sshlog(
                b"kex.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"kex_input_ext_info\0",
                ))
                .as_ptr(),
                573 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"%s=<%s>\0" as *const u8 as *const libc::c_char,
                name,
                val,
            );
            if libc::strcmp(
                val as *const libc::c_char,
                b"0\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
            {
                (*kex).flags |= 0x4 as libc::c_int as libc::c_uint;
            } else {
                crate::log::sshlog(
                    b"kex.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"kex_input_ext_info\0",
                    ))
                    .as_ptr(),
                    578 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"unsupported version of %s extension\0" as *const u8 as *const libc::c_char,
                    name,
                );
            }
        } else {
            crate::log::sshlog(
                b"kex.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"kex_input_ext_info\0",
                ))
                .as_ptr(),
                581 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"%s (unrecognised)\0" as *const u8 as *const libc::c_char,
                name,
            );
        }
        libc::free(name as *mut libc::c_void);
        libc::free(val as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    return sshpkt_get_end(ssh);
}
unsafe extern "C" fn kex_input_newkeys(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"kex_input_newkeys\0"))
            .as_ptr(),
        594 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"SSH2_MSG_NEWKEYS received\0" as *const u8 as *const libc::c_char,
    );
    ssh_dispatch_set(
        ssh,
        21 as libc::c_int,
        Some(
            kex_protocol_error
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        20 as libc::c_int,
        Some(
            kex_input_kexinit
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    r = sshpkt_get_end(ssh);
    if r != 0 as libc::c_int {
        return r;
    }
    r = ssh_set_newkeys(ssh, MODE_IN as libc::c_int);
    if r != 0 as libc::c_int {
        return r;
    }
    (*kex).done = 1 as libc::c_int;
    (*kex).flags &= !(0x2 as libc::c_int) as libc::c_uint;
    sshbuf_reset((*kex).peer);
    (*kex).flags &= !(0x1 as libc::c_int) as libc::c_uint;
    libc::free((*kex).name as *mut libc::c_void);
    (*kex).name = 0 as *mut libc::c_char;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn kex_send_kexinit(mut ssh: *mut ssh) -> libc::c_int {
    let mut cookie: *mut u_char = 0 as *mut u_char;
    let mut kex: *mut kex = (*ssh).kex;
    let mut r: libc::c_int = 0;
    if kex.is_null() {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"kex_send_kexinit\0"))
                .as_ptr(),
            619 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no kex\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if (*kex).flags & 0x1 as libc::c_int as libc::c_uint != 0 {
        return 0 as libc::c_int;
    }
    (*kex).done = 0 as libc::c_int;
    if sshbuf_len((*kex).my) < 16 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"kex_send_kexinit\0"))
                .as_ptr(),
            629 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"bad kex length: %zu < %d\0" as *const u8 as *const libc::c_char,
            sshbuf_len((*kex).my),
            16 as libc::c_int,
        );
        return -(4 as libc::c_int);
    }
    cookie = sshbuf_mutable_ptr((*kex).my);
    if cookie.is_null() {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"kex_send_kexinit\0"))
                .as_ptr(),
            633 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"buffer error\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    arc4random_buf(cookie as *mut libc::c_void, 16 as libc::c_int as size_t);
    r = sshpkt_start(ssh, 20 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_putb(ssh, (*kex).my);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"kex_send_kexinit\0"))
                .as_ptr(),
            641 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"compose reply\0" as *const u8 as *const libc::c_char,
        );
        return r;
    }
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"kex_send_kexinit\0")).as_ptr(),
        644 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"SSH2_MSG_KEXINIT sent\0" as *const u8 as *const libc::c_char,
    );
    (*kex).flags |= 0x1 as libc::c_int as libc::c_uint;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn kex_input_kexinit(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    let mut ptr: *const u_char = 0 as *const u_char;
    let mut i: u_int = 0;
    let mut dlen: size_t = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"kex_input_kexinit\0"))
            .as_ptr(),
        658 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"SSH2_MSG_KEXINIT received\0" as *const u8 as *const libc::c_char,
    );
    if kex.is_null() {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"kex_input_kexinit\0"))
                .as_ptr(),
            660 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no kex\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    ssh_dispatch_set(ssh, 20 as libc::c_int, None);
    ptr = sshpkt_ptr(ssh, &mut dlen);
    r = sshbuf_put((*kex).peer, ptr as *const libc::c_void, dlen);
    if r != 0 as libc::c_int {
        return r;
    }
    i = 0 as libc::c_int as u_int;
    while i < 16 as libc::c_int as libc::c_uint {
        r = sshpkt_get_u8(ssh, 0 as *mut u_char);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"kex.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"kex_input_kexinit\0"))
                    .as_ptr(),
                671 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"discard cookie\0" as *const u8 as *const libc::c_char,
            );
            return r;
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < PROPOSAL_MAX as libc::c_int as libc::c_uint {
        r = sshpkt_get_string(ssh, 0 as *mut *mut u_char, 0 as *mut size_t);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"kex.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"kex_input_kexinit\0"))
                    .as_ptr(),
                677 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"discard proposal\0" as *const u8 as *const libc::c_char,
            );
            return r;
        }
        i = i.wrapping_add(1);
        i;
    }
    r = sshpkt_get_u8(ssh, 0 as *mut u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_get_u32(ssh, 0 as *mut u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    if (*kex).flags & 0x1 as libc::c_int as libc::c_uint == 0 {
        r = kex_send_kexinit(ssh);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    r = kex_choose_conf(ssh);
    if r != 0 as libc::c_int {
        return r;
    }
    if (*kex).kex_type < KEX_MAX as libc::c_int as libc::c_uint
        && ((*kex).kex[(*kex).kex_type as usize]).is_some()
    {
        return ((*kex).kex[(*kex).kex_type as usize]).expect("non-null function pointer")(ssh);
    }
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"kex_input_kexinit\0"))
            .as_ptr(),
        705 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"unknown kex type %u\0" as *const u8 as *const libc::c_char,
        (*kex).kex_type,
    );
    return -(1 as libc::c_int);
}
pub unsafe extern "C" fn kex_new() -> *mut kex {
    let mut kex: *mut kex = 0 as *mut kex;
    kex = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<kex>() as libc::c_ulong,
    ) as *mut kex;
    if kex.is_null()
        || {
            (*kex).peer = crate::sshbuf::sshbuf_new();
            ((*kex).peer).is_null()
        }
        || {
            (*kex).my = crate::sshbuf::sshbuf_new();
            ((*kex).my).is_null()
        }
        || {
            (*kex).client_version = crate::sshbuf::sshbuf_new();
            ((*kex).client_version).is_null()
        }
        || {
            (*kex).server_version = crate::sshbuf::sshbuf_new();
            ((*kex).server_version).is_null()
        }
        || {
            (*kex).session_id = crate::sshbuf::sshbuf_new();
            ((*kex).session_id).is_null()
        }
    {
        kex_free(kex);
        return 0 as *mut kex;
    }
    return kex;
}
pub unsafe extern "C" fn kex_free_newkeys(mut newkeys: *mut newkeys) {
    if newkeys.is_null() {
        return;
    }
    if !((*newkeys).enc.key).is_null() {
        explicit_bzero(
            (*newkeys).enc.key as *mut libc::c_void,
            (*newkeys).enc.key_len as size_t,
        );
        libc::free((*newkeys).enc.key as *mut libc::c_void);
        (*newkeys).enc.key = 0 as *mut u_char;
    }
    if !((*newkeys).enc.iv).is_null() {
        explicit_bzero(
            (*newkeys).enc.iv as *mut libc::c_void,
            (*newkeys).enc.iv_len as size_t,
        );
        libc::free((*newkeys).enc.iv as *mut libc::c_void);
        (*newkeys).enc.iv = 0 as *mut u_char;
    }
    libc::free((*newkeys).enc.name as *mut libc::c_void);
    explicit_bzero(
        &mut (*newkeys).enc as *mut sshenc as *mut libc::c_void,
        ::core::mem::size_of::<sshenc>() as libc::c_ulong,
    );
    libc::free((*newkeys).comp.name as *mut libc::c_void);
    explicit_bzero(
        &mut (*newkeys).comp as *mut sshcomp as *mut libc::c_void,
        ::core::mem::size_of::<sshcomp>() as libc::c_ulong,
    );
    mac_clear(&mut (*newkeys).mac);
    if !((*newkeys).mac.key).is_null() {
        explicit_bzero(
            (*newkeys).mac.key as *mut libc::c_void,
            (*newkeys).mac.key_len as size_t,
        );
        libc::free((*newkeys).mac.key as *mut libc::c_void);
        (*newkeys).mac.key = 0 as *mut u_char;
    }
    libc::free((*newkeys).mac.name as *mut libc::c_void);
    explicit_bzero(
        &mut (*newkeys).mac as *mut sshmac as *mut libc::c_void,
        ::core::mem::size_of::<sshmac>() as libc::c_ulong,
    );
    freezero(
        newkeys as *mut libc::c_void,
        ::core::mem::size_of::<newkeys>() as libc::c_ulong,
    );
}
pub unsafe extern "C" fn kex_free(mut kex: *mut kex) {
    let mut mode: u_int = 0;
    if kex.is_null() {
        return;
    }
    DH_free((*kex).dh);
    EC_KEY_free((*kex).ec_client_key);
    mode = 0 as libc::c_int as u_int;
    while mode < MODE_MAX as libc::c_int as libc::c_uint {
        kex_free_newkeys((*kex).newkeys[mode as usize]);
        (*kex).newkeys[mode as usize] = 0 as *mut newkeys;
        mode = mode.wrapping_add(1);
        mode;
    }
    crate::sshbuf::sshbuf_free((*kex).peer);
    crate::sshbuf::sshbuf_free((*kex).my);
    crate::sshbuf::sshbuf_free((*kex).client_version);
    crate::sshbuf::sshbuf_free((*kex).server_version);
    crate::sshbuf::sshbuf_free((*kex).client_pub);
    crate::sshbuf::sshbuf_free((*kex).session_id);
    crate::sshbuf::sshbuf_free((*kex).initial_sig);
    sshkey_free((*kex).initial_hostkey);
    libc::free((*kex).failed_choice as *mut libc::c_void);
    libc::free((*kex).hostkey_alg as *mut libc::c_void);
    libc::free((*kex).name as *mut libc::c_void);
    libc::free(kex as *mut libc::c_void);
}
pub unsafe extern "C" fn kex_ready(
    mut ssh: *mut ssh,
    mut proposal: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = kex_prop2buf((*(*ssh).kex).my, proposal);
    if r != 0 as libc::c_int {
        return r;
    }
    (*(*ssh).kex).flags = 0x2 as libc::c_int as u_int;
    kex_reset_dispatch(ssh);
    ssh_dispatch_set(
        ssh,
        20 as libc::c_int,
        Some(
            kex_input_kexinit
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn kex_setup(
    mut ssh: *mut ssh,
    mut proposal: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = kex_ready(ssh, proposal);
    if r != 0 as libc::c_int {
        return r;
    }
    r = kex_send_kexinit(ssh);
    if r != 0 as libc::c_int {
        kex_free((*ssh).kex);
        (*ssh).kex = 0 as *mut kex;
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn kex_start_rekex(mut ssh: *mut ssh) -> libc::c_int {
    if ((*ssh).kex).is_null() {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"kex_start_rekex\0"))
                .as_ptr(),
            824 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no kex\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if (*(*ssh).kex).done == 0 as libc::c_int {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"kex_start_rekex\0"))
                .as_ptr(),
            828 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"requested twice\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    (*(*ssh).kex).done = 0 as libc::c_int;
    return kex_send_kexinit(ssh);
}
unsafe extern "C" fn choose_enc(
    mut enc: *mut sshenc,
    mut client: *mut libc::c_char,
    mut server: *mut libc::c_char,
) -> libc::c_int {
    let mut name: *mut libc::c_char = match_list(client, server, 0 as *mut u_int);
    if name.is_null() {
        return -(31 as libc::c_int);
    }
    (*enc).cipher = cipher_by_name(name);
    if ((*enc).cipher).is_null() {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"choose_enc\0")).as_ptr(),
            843 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"unsupported cipher %s\0" as *const u8 as *const libc::c_char,
            name,
        );
        libc::free(name as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    (*enc).name = name;
    (*enc).enabled = 0 as libc::c_int;
    (*enc).iv = 0 as *mut u_char;
    (*enc).iv_len = cipher_ivlen((*enc).cipher);
    (*enc).key = 0 as *mut u_char;
    (*enc).key_len = cipher_keylen((*enc).cipher);
    (*enc).block_size = cipher_blocksize((*enc).cipher);
    return 0 as libc::c_int;
}
unsafe extern "C" fn choose_mac(
    mut _ssh: *mut ssh,
    mut mac: *mut sshmac,
    mut client: *mut libc::c_char,
    mut server: *mut libc::c_char,
) -> libc::c_int {
    let mut name: *mut libc::c_char = match_list(client, server, 0 as *mut u_int);
    if name.is_null() {
        return -(32 as libc::c_int);
    }
    if mac_setup(mac, name) < 0 as libc::c_int {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"choose_mac\0")).as_ptr(),
            865 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"unsupported MAC %s\0" as *const u8 as *const libc::c_char,
            name,
        );
        libc::free(name as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    (*mac).name = name;
    (*mac).key = 0 as *mut u_char;
    (*mac).enabled = 0 as libc::c_int;
    return 0 as libc::c_int;
}
unsafe extern "C" fn choose_comp(
    mut comp: *mut sshcomp,
    mut client: *mut libc::c_char,
    mut server: *mut libc::c_char,
) -> libc::c_int {
    let mut name: *mut libc::c_char = match_list(client, server, 0 as *mut u_int);
    if name.is_null() {
        return -(33 as libc::c_int);
    }
    if libc::strcmp(
        name,
        b"zlib@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        (*comp).type_0 = 2 as libc::c_int as u_int;
    } else if libc::strcmp(name, b"zlib\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        (*comp).type_0 = 1 as libc::c_int as u_int;
    } else if libc::strcmp(name, b"none\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        (*comp).type_0 = 0 as libc::c_int as u_int;
    } else {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"choose_comp\0")).as_ptr(),
            892 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"unsupported compression scheme %s\0" as *const u8 as *const libc::c_char,
            name,
        );
        libc::free(name as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    (*comp).name = name;
    return 0 as libc::c_int;
}
unsafe extern "C" fn choose_kex(
    mut k: *mut kex,
    mut client: *mut libc::c_char,
    mut server: *mut libc::c_char,
) -> libc::c_int {
    let mut kexalg: *const kexalg = 0 as *const kexalg;
    (*k).name = match_list(client, server, 0 as *mut u_int);
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"choose_kex\0")).as_ptr(),
        907 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"kex: algorithm: %s\0" as *const u8 as *const libc::c_char,
        if !((*k).name).is_null() {
            (*k).name as *const libc::c_char
        } else {
            b"(no match)\0" as *const u8 as *const libc::c_char
        },
    );
    if ((*k).name).is_null() {
        return -(34 as libc::c_int);
    }
    kexalg = kex_alg_by_name((*k).name);
    if kexalg.is_null() {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"choose_kex\0")).as_ptr(),
            911 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"unsupported KEX method %s\0" as *const u8 as *const libc::c_char,
            (*k).name,
        );
        return -(1 as libc::c_int);
    }
    (*k).kex_type = (*kexalg).type_0;
    (*k).hash_alg = (*kexalg).hash_alg;
    (*k).ec_nid = (*kexalg).ec_nid;
    return 0 as libc::c_int;
}
unsafe extern "C" fn choose_hostkeyalg(
    mut k: *mut kex,
    mut client: *mut libc::c_char,
    mut server: *mut libc::c_char,
) -> libc::c_int {
    libc::free((*k).hostkey_alg as *mut libc::c_void);
    (*k).hostkey_alg = match_list(client, server, 0 as *mut u_int);
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"choose_hostkeyalg\0"))
            .as_ptr(),
        927 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"kex: host key algorithm: %s\0" as *const u8 as *const libc::c_char,
        if !((*k).hostkey_alg).is_null() {
            (*k).hostkey_alg as *const libc::c_char
        } else {
            b"(no match)\0" as *const u8 as *const libc::c_char
        },
    );
    if ((*k).hostkey_alg).is_null() {
        return -(35 as libc::c_int);
    }
    (*k).hostkey_type = sshkey_type_from_name((*k).hostkey_alg);
    if (*k).hostkey_type == KEY_UNSPEC as libc::c_int {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"choose_hostkeyalg\0"))
                .as_ptr(),
            932 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"unsupported hostkey algorithm %s\0" as *const u8 as *const libc::c_char,
            (*k).hostkey_alg,
        );
        return -(1 as libc::c_int);
    }
    (*k).hostkey_nid = sshkey_ecdsa_nid_from_name((*k).hostkey_alg);
    return 0 as libc::c_int;
}
unsafe extern "C" fn proposals_match(
    mut my: *mut *mut libc::c_char,
    mut peer: *mut *mut libc::c_char,
) -> libc::c_int {
    static mut check: [libc::c_int; 3] = [
        PROPOSAL_KEX_ALGS as libc::c_int,
        PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int,
        -(1 as libc::c_int),
    ];
    let mut idx: *mut libc::c_int = 0 as *mut libc::c_int;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    idx = &mut *check.as_mut_ptr().offset(0 as libc::c_int as isize) as *mut libc::c_int;
    while *idx != -(1 as libc::c_int) {
        p = libc::strchr(*my.offset(*idx as isize), ',' as i32);
        if !p.is_null() {
            *p = '\0' as i32 as libc::c_char;
        }
        p = libc::strchr(*peer.offset(*idx as isize), ',' as i32);
        if !p.is_null() {
            *p = '\0' as i32 as libc::c_char;
        }
        if libc::strcmp(*my.offset(*idx as isize), *peer.offset(*idx as isize)) != 0 as libc::c_int
        {
            crate::log::sshlog(
                b"kex.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"proposals_match\0"))
                    .as_ptr(),
                955 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"proposal mismatch: my %s peer %s\0" as *const u8 as *const libc::c_char,
                *my.offset(*idx as isize),
                *peer.offset(*idx as isize),
            );
            return 0 as libc::c_int;
        }
        idx = idx.offset(1);
        idx;
    }
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"proposals_match\0")).as_ptr(),
        959 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"proposals match\0" as *const u8 as *const libc::c_char,
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn has_any_alg(
    mut proposal: *const libc::c_char,
    mut algs: *const libc::c_char,
) -> libc::c_int {
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    cp = match_list(proposal, algs, 0 as *mut u_int);
    if cp.is_null() {
        return 0 as libc::c_int;
    }
    libc::free(cp as *mut libc::c_void);
    return 1 as libc::c_int;
}
unsafe extern "C" fn kex_choose_conf(mut ssh: *mut ssh) -> libc::c_int {
    let mut current_block: u64;
    let mut kex: *mut kex = (*ssh).kex;
    let mut newkeys: *mut newkeys = 0 as *mut newkeys;
    let mut my: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut peer: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut cprop: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut sprop: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut nenc: libc::c_int = 0;
    let mut nmac: libc::c_int = 0;
    let mut ncomp: libc::c_int = 0;
    let mut mode: u_int = 0;
    let mut ctos: u_int = 0;
    let mut need: u_int = 0;
    let mut dh_need: u_int = 0;
    let mut authlen: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut first_kex_follows: libc::c_int = 0;
    crate::log::sshlog(
        b"kex.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"kex_choose_conf\0")).as_ptr(),
        986 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"local %s KEXINIT proposal\0" as *const u8 as *const libc::c_char,
        if (*kex).server != 0 {
            b"server\0" as *const u8 as *const libc::c_char
        } else {
            b"client\0" as *const u8 as *const libc::c_char
        },
    );
    r = kex_buf2prop((*kex).my, 0 as *mut libc::c_int, &mut my);
    if !(r != 0 as libc::c_int) {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"kex_choose_conf\0"))
                .as_ptr(),
            989 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"peer %s KEXINIT proposal\0" as *const u8 as *const libc::c_char,
            if (*kex).server != 0 {
                b"client\0" as *const u8 as *const libc::c_char
            } else {
                b"server\0" as *const u8 as *const libc::c_char
            },
        );
        r = kex_buf2prop((*kex).peer, &mut first_kex_follows, &mut peer);
        if !(r != 0 as libc::c_int) {
            if (*kex).server != 0 {
                cprop = peer;
                sprop = my;
            } else {
                cprop = my;
                sprop = peer;
            }
            if (*kex).server != 0 && (*kex).flags & 0x2 as libc::c_int as libc::c_uint != 0 {
                let mut ext: *mut libc::c_char = 0 as *mut libc::c_char;
                ext = match_list(
                    b"ext-info-c\0" as *const u8 as *const libc::c_char,
                    *peer.offset(PROPOSAL_KEX_ALGS as libc::c_int as isize),
                    0 as *mut u_int,
                );
                (*kex).ext_info_c =
                    (ext != 0 as *mut libc::c_void as *mut libc::c_char) as libc::c_int;
                libc::free(ext as *mut libc::c_void);
            }
            if (*kex).server != 0 && (*kex).flags & 0x2 as libc::c_int as libc::c_uint != 0 {
                if has_any_alg(
                    *peer.offset(PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as isize),
                    b"rsa-sha2-256,rsa-sha2-256-cert-v01@openssh.com\0" as *const u8
                        as *const libc::c_char,
                ) != 0
                {
                    (*kex).flags |= 0x8 as libc::c_int as libc::c_uint;
                }
                if has_any_alg(
                    *peer.offset(PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as isize),
                    b"rsa-sha2-512,rsa-sha2-512-cert-v01@openssh.com\0" as *const u8
                        as *const libc::c_char,
                ) != 0
                {
                    (*kex).flags |= 0x10 as libc::c_int as libc::c_uint;
                }
            }
            r = choose_kex(
                kex,
                *cprop.offset(PROPOSAL_KEX_ALGS as libc::c_int as isize),
                *sprop.offset(PROPOSAL_KEX_ALGS as libc::c_int as isize),
            );
            if r != 0 as libc::c_int {
                (*kex).failed_choice = *peer.offset(PROPOSAL_KEX_ALGS as libc::c_int as isize);
                let ref mut fresh7 = *peer.offset(PROPOSAL_KEX_ALGS as libc::c_int as isize);
                *fresh7 = 0 as *mut libc::c_char;
            } else {
                r = choose_hostkeyalg(
                    kex,
                    *cprop.offset(PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as isize),
                    *sprop.offset(PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as isize),
                );
                if r != 0 as libc::c_int {
                    (*kex).failed_choice =
                        *peer.offset(PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as isize);
                    let ref mut fresh8 =
                        *peer.offset(PROPOSAL_SERVER_HOST_KEY_ALGS as libc::c_int as isize);
                    *fresh8 = 0 as *mut libc::c_char;
                } else {
                    mode = 0 as libc::c_int as u_int;
                    loop {
                        if !(mode < MODE_MAX as libc::c_int as libc::c_uint) {
                            current_block = 12199444798915819164;
                            break;
                        }
                        newkeys = calloc(
                            1 as libc::c_int as libc::c_ulong,
                            ::core::mem::size_of::<newkeys>() as libc::c_ulong,
                        ) as *mut newkeys;
                        if newkeys.is_null() {
                            r = -(2 as libc::c_int);
                            current_block = 11763037568314306996;
                            break;
                        } else {
                            (*kex).newkeys[mode as usize] = newkeys;
                            ctos = ((*kex).server == 0
                                && mode == MODE_OUT as libc::c_int as libc::c_uint
                                || (*kex).server != 0
                                    && mode == MODE_IN as libc::c_int as libc::c_uint)
                                as libc::c_int as u_int;
                            nenc = if ctos != 0 {
                                PROPOSAL_ENC_ALGS_CTOS as libc::c_int
                            } else {
                                PROPOSAL_ENC_ALGS_STOC as libc::c_int
                            };
                            nmac = if ctos != 0 {
                                PROPOSAL_MAC_ALGS_CTOS as libc::c_int
                            } else {
                                PROPOSAL_MAC_ALGS_STOC as libc::c_int
                            };
                            ncomp = if ctos != 0 {
                                PROPOSAL_COMP_ALGS_CTOS as libc::c_int
                            } else {
                                PROPOSAL_COMP_ALGS_STOC as libc::c_int
                            };
                            r = choose_enc(
                                &mut (*newkeys).enc,
                                *cprop.offset(nenc as isize),
                                *sprop.offset(nenc as isize),
                            );
                            if r != 0 as libc::c_int {
                                (*kex).failed_choice = *peer.offset(nenc as isize);
                                let ref mut fresh9 = *peer.offset(nenc as isize);
                                *fresh9 = 0 as *mut libc::c_char;
                                current_block = 11763037568314306996;
                                break;
                            } else {
                                authlen = cipher_authlen((*newkeys).enc.cipher);
                                if authlen == 0 as libc::c_int as libc::c_uint && {
                                    r = choose_mac(
                                        ssh,
                                        &mut (*newkeys).mac,
                                        *cprop.offset(nmac as isize),
                                        *sprop.offset(nmac as isize),
                                    );
                                    r != 0 as libc::c_int
                                } {
                                    (*kex).failed_choice = *peer.offset(nmac as isize);
                                    let ref mut fresh10 = *peer.offset(nmac as isize);
                                    *fresh10 = 0 as *mut libc::c_char;
                                    current_block = 11763037568314306996;
                                    break;
                                } else {
                                    r = choose_comp(
                                        &mut (*newkeys).comp,
                                        *cprop.offset(ncomp as isize),
                                        *sprop.offset(ncomp as isize),
                                    );
                                    if r != 0 as libc::c_int {
                                        (*kex).failed_choice = *peer.offset(ncomp as isize);
                                        let ref mut fresh11 = *peer.offset(ncomp as isize);
                                        *fresh11 = 0 as *mut libc::c_char;
                                        current_block = 11763037568314306996;
                                        break;
                                    } else {
                                        crate::log::sshlog(
                                            b"kex.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 16],
                                                &[libc::c_char; 16],
                                            >(
                                                b"kex_choose_conf\0"
                                            ))
                                            .as_ptr(),
                                            1069 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_DEBUG1,
                                            0 as *const libc::c_char,
                                            b"kex: %s cipher: %s MAC: %s compression: %s\0"
                                                as *const u8
                                                as *const libc::c_char,
                                            if ctos != 0 {
                                                b"client->server\0" as *const u8
                                                    as *const libc::c_char
                                            } else {
                                                b"server->client\0" as *const u8
                                                    as *const libc::c_char
                                            },
                                            (*newkeys).enc.name,
                                            if authlen == 0 as libc::c_int as libc::c_uint {
                                                (*newkeys).mac.name as *const libc::c_char
                                            } else {
                                                b"<implicit>\0" as *const u8 as *const libc::c_char
                                            },
                                            (*newkeys).comp.name,
                                        );
                                        mode = mode.wrapping_add(1);
                                        mode;
                                    }
                                }
                            }
                        }
                    }
                    match current_block {
                        11763037568314306996 => {}
                        _ => {
                            dh_need = 0 as libc::c_int as u_int;
                            need = dh_need;
                            mode = 0 as libc::c_int as u_int;
                            while mode < MODE_MAX as libc::c_int as libc::c_uint {
                                newkeys = (*kex).newkeys[mode as usize];
                                need = if need > (*newkeys).enc.key_len {
                                    need
                                } else {
                                    (*newkeys).enc.key_len
                                };
                                need = if need > (*newkeys).enc.block_size {
                                    need
                                } else {
                                    (*newkeys).enc.block_size
                                };
                                need = if need > (*newkeys).enc.iv_len {
                                    need
                                } else {
                                    (*newkeys).enc.iv_len
                                };
                                need = if need > (*newkeys).mac.key_len {
                                    need
                                } else {
                                    (*newkeys).mac.key_len
                                };
                                dh_need = if dh_need > cipher_seclen((*newkeys).enc.cipher) {
                                    dh_need
                                } else {
                                    cipher_seclen((*newkeys).enc.cipher)
                                };
                                dh_need = if dh_need > (*newkeys).enc.block_size {
                                    dh_need
                                } else {
                                    (*newkeys).enc.block_size
                                };
                                dh_need = if dh_need > (*newkeys).enc.iv_len {
                                    dh_need
                                } else {
                                    (*newkeys).enc.iv_len
                                };
                                dh_need = if dh_need > (*newkeys).mac.key_len {
                                    dh_need
                                } else {
                                    (*newkeys).mac.key_len
                                };
                                mode = mode.wrapping_add(1);
                                mode;
                            }
                            (*kex).we_need = need;
                            (*kex).dh_need = dh_need;
                            if first_kex_follows != 0 && proposals_match(my, peer) == 0 {
                                (*ssh).dispatch_skip_packets = 1 as libc::c_int;
                            }
                            r = 0 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    kex_prop_free(my);
    kex_prop_free(peer);
    return r;
}
unsafe extern "C" fn derive_key(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut need: u_int,
    mut hash: *mut u_char,
    mut hashlen: u_int,
    mut shared_secret: *const crate::sshbuf::sshbuf,
    mut keyp: *mut *mut u_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut kex: *mut kex = (*ssh).kex;
    let mut hashctx: *mut ssh_digest_ctx = 0 as *mut ssh_digest_ctx;
    let mut c: libc::c_char = id as libc::c_char;
    let mut have: u_int = 0;
    let mut mdsz: size_t = 0;
    let mut digest: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    mdsz = ssh_digest_bytes((*kex).hash_alg);
    if mdsz == 0 as libc::c_int as libc::c_ulong {
        return -(10 as libc::c_int);
    }
    digest = calloc(
        1 as libc::c_int as libc::c_ulong,
        (need as libc::c_ulong)
            .wrapping_add(mdsz.wrapping_sub(1 as libc::c_int as libc::c_ulong))
            .wrapping_div(mdsz)
            .wrapping_mul(mdsz),
    ) as *mut u_char;
    if digest.is_null() {
        r = -(2 as libc::c_int);
    } else {
        hashctx = ssh_digest_start((*kex).hash_alg);
        if hashctx.is_null()
            || ssh_digest_update_buffer(hashctx, shared_secret) != 0 as libc::c_int
            || ssh_digest_update(hashctx, hash as *const libc::c_void, hashlen as size_t)
                != 0 as libc::c_int
            || ssh_digest_update(
                hashctx,
                &mut c as *mut libc::c_char as *const libc::c_void,
                1 as libc::c_int as size_t,
            ) != 0 as libc::c_int
            || ssh_digest_update_buffer(hashctx, (*kex).session_id) != 0 as libc::c_int
            || ssh_digest_final(hashctx, digest, mdsz) != 0 as libc::c_int
        {
            r = -(22 as libc::c_int);
            crate::log::sshlog(
                b"kex.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"derive_key\0"))
                    .as_ptr(),
                1124 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"KEX hash failed\0" as *const u8 as *const libc::c_char,
            );
        } else {
            ssh_digest_free(hashctx);
            hashctx = 0 as *mut ssh_digest_ctx;
            have = mdsz as u_int;
            loop {
                if !(need > have) {
                    current_block = 8831408221741692167;
                    break;
                }
                hashctx = ssh_digest_start((*kex).hash_alg);
                if hashctx.is_null()
                    || ssh_digest_update_buffer(hashctx, shared_secret) != 0 as libc::c_int
                    || ssh_digest_update(hashctx, hash as *const libc::c_void, hashlen as size_t)
                        != 0 as libc::c_int
                    || ssh_digest_update(hashctx, digest as *const libc::c_void, have as size_t)
                        != 0 as libc::c_int
                    || ssh_digest_final(hashctx, digest.offset(have as isize), mdsz)
                        != 0 as libc::c_int
                {
                    crate::log::sshlog(
                        b"kex.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                            b"derive_key\0",
                        ))
                        .as_ptr(),
                        1141 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"KDF failed\0" as *const u8 as *const libc::c_char,
                    );
                    r = -(22 as libc::c_int);
                    current_block = 8521021500030589103;
                    break;
                } else {
                    ssh_digest_free(hashctx);
                    hashctx = 0 as *mut ssh_digest_ctx;
                    have = (have as libc::c_ulong).wrapping_add(mdsz) as u_int as u_int;
                }
            }
            match current_block {
                8521021500030589103 => {}
                _ => {
                    *keyp = digest;
                    digest = 0 as *mut u_char;
                    r = 0 as libc::c_int;
                }
            }
        }
    }
    libc::free(digest as *mut libc::c_void);
    ssh_digest_free(hashctx);
    return r;
}
pub unsafe extern "C" fn kex_derive_keys(
    mut ssh: *mut ssh,
    mut hash: *mut u_char,
    mut hashlen: u_int,
    mut shared_secret: *const crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    let mut keys: [*mut u_char; 6] = [0 as *mut u_char; 6];
    let mut i: u_int = 0;
    let mut j: u_int = 0;
    let mut mode: u_int = 0;
    let mut ctos: u_int = 0;
    let mut r: libc::c_int = 0;
    if (*kex).flags & 0x2 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint {
        if sshbuf_len((*kex).session_id) != 0 as libc::c_int as libc::c_ulong {
            crate::log::sshlog(
                b"kex.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"kex_derive_keys\0"))
                    .as_ptr(),
                1174 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"already have session ID at kex\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        r = sshbuf_put(
            (*kex).session_id,
            hash as *const libc::c_void,
            hashlen as size_t,
        );
        if r != 0 as libc::c_int {
            return r;
        }
    } else if sshbuf_len((*kex).session_id) == 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"kex_derive_keys\0"))
                .as_ptr(),
            1180 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no session ID in rekex\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int as u_int;
    while i < 6 as libc::c_int as libc::c_uint {
        r = derive_key(
            ssh,
            ('A' as i32 as libc::c_uint).wrapping_add(i) as libc::c_int,
            (*kex).we_need,
            hash,
            hashlen,
            shared_secret,
            &mut *keys.as_mut_ptr().offset(i as isize),
        );
        if r != 0 as libc::c_int {
            j = 0 as libc::c_int as u_int;
            while j < i {
                libc::free(keys[j as usize] as *mut libc::c_void);
                j = j.wrapping_add(1);
                j;
            }
            return r;
        }
        i = i.wrapping_add(1);
        i;
    }
    mode = 0 as libc::c_int as u_int;
    while mode < MODE_MAX as libc::c_int as libc::c_uint {
        ctos = ((*kex).server == 0 && mode == MODE_OUT as libc::c_int as libc::c_uint
            || (*kex).server != 0 && mode == MODE_IN as libc::c_int as libc::c_uint)
            as libc::c_int as u_int;
        (*(*kex).newkeys[mode as usize]).enc.iv = keys[(if ctos != 0 {
            0 as libc::c_int
        } else {
            1 as libc::c_int
        }) as usize];
        (*(*kex).newkeys[mode as usize]).enc.key = keys[(if ctos != 0 {
            2 as libc::c_int
        } else {
            3 as libc::c_int
        }) as usize];
        (*(*kex).newkeys[mode as usize]).mac.key = keys[(if ctos != 0 {
            4 as libc::c_int
        } else {
            5 as libc::c_int
        }) as usize];
        mode = mode.wrapping_add(1);
        mode;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn kex_load_hostkey(
    mut ssh: *mut ssh,
    mut prvp: *mut *mut sshkey,
    mut pubp: *mut *mut sshkey,
) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    *pubp = 0 as *mut sshkey;
    *prvp = 0 as *mut sshkey;
    if ((*kex).load_host_public_key).is_none() || ((*kex).load_host_private_key).is_none() {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"kex_load_hostkey\0"))
                .as_ptr(),
            1210 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"missing hostkey loader\0" as *const u8 as *const libc::c_char,
        );
        return -(10 as libc::c_int);
    }
    *pubp = ((*kex).load_host_public_key).expect("non-null function pointer")(
        (*kex).hostkey_type,
        (*kex).hostkey_nid,
        ssh,
    );
    *prvp = ((*kex).load_host_private_key).expect("non-null function pointer")(
        (*kex).hostkey_type,
        (*kex).hostkey_nid,
        ssh,
    );
    if (*pubp).is_null() {
        return -(36 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn kex_verify_host_key(
    mut ssh: *mut ssh,
    mut server_host_key: *mut sshkey,
) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    if ((*kex).verify_host_key).is_none() {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"kex_verify_host_key\0"))
                .as_ptr(),
            1228 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"missing hostkey verifier\0" as *const u8 as *const libc::c_char,
        );
        return -(10 as libc::c_int);
    }
    if (*server_host_key).type_0 != (*kex).hostkey_type
        || (*kex).hostkey_type == KEY_ECDSA as libc::c_int
            && (*server_host_key).ecdsa_nid != (*kex).hostkey_nid
    {
        return -(13 as libc::c_int);
    }
    if ((*kex).verify_host_key).expect("non-null function pointer")(server_host_key, ssh)
        == -(1 as libc::c_int)
    {
        return -(21 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn send_error(mut ssh: *mut ssh, mut msg: *mut libc::c_char) {
    let mut crnl: *mut libc::c_char =
        b"\r\n\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    if (*(*ssh).kex).server == 0 {
        return;
    }
    if atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        ssh_packet_get_connection_out(ssh),
        msg as *mut libc::c_void,
        strlen(msg),
    ) != strlen(msg)
        || atomicio(
            ::core::mem::transmute::<
                Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
                Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
            >(Some(
                write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
            )),
            ssh_packet_get_connection_out(ssh),
            crnl as *mut libc::c_void,
            strlen(crnl),
        ) != strlen(crnl)
    {
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"send_error\0")).as_ptr(),
            1265 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"write: %.100s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
}
pub unsafe extern "C" fn kex_exchange_identification(
    mut ssh: *mut ssh,
    mut timeout_ms: libc::c_int,
    mut version_addendum: *const libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut remote_major: libc::c_int = 0;
    let mut remote_minor: libc::c_int = 0;
    let mut mismatch: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0 as libc::c_int;
    let mut len: size_t = 0;
    let mut n: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut expect_nl: libc::c_int = 0;
    let mut c: u_char = 0;
    let mut our_version: *mut crate::sshbuf::sshbuf = if (*(*ssh).kex).server != 0 {
        (*(*ssh).kex).server_version
    } else {
        (*(*ssh).kex).client_version
    };
    let mut peer_version: *mut crate::sshbuf::sshbuf = if (*(*ssh).kex).server != 0 {
        (*(*ssh).kex).client_version
    } else {
        (*(*ssh).kex).server_version
    };
    let mut our_version_string: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut peer_version_string: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut remote_version: *mut libc::c_char = 0 as *mut libc::c_char;
    sshbuf_reset(our_version);
    if !version_addendum.is_null() && *version_addendum as libc::c_int == '\0' as i32 {
        version_addendum = 0 as *const libc::c_char;
    }
    r = crate::sshbuf_getput_basic::sshbuf_putf(
        our_version,
        b"SSH-%d.%d-%.100s%s%s\r\n\0" as *const u8 as *const libc::c_char,
        2 as libc::c_int,
        0 as libc::c_int,
        b"OpenSSH_9.3\0" as *const u8 as *const libc::c_char,
        if version_addendum.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b" \0" as *const u8 as *const libc::c_char
        },
        if version_addendum.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            version_addendum
        },
    );
    if r != 0 as libc::c_int {
        oerrno = *libc::__errno_location();
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"kex_exchange_identification\0",
            ))
            .as_ptr(),
            1297 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"crate::sshbuf_getput_basic::sshbuf_putf\0" as *const u8 as *const libc::c_char,
        );
    } else if atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        ssh_packet_get_connection_out(ssh),
        sshbuf_mutable_ptr(our_version) as *mut libc::c_void,
        sshbuf_len(our_version),
    ) != sshbuf_len(our_version)
    {
        oerrno = *libc::__errno_location();
        crate::log::sshlog(
            b"kex.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"kex_exchange_identification\0",
            ))
            .as_ptr(),
            1305 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"write: %.100s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        r = -(24 as libc::c_int);
    } else {
        r = sshbuf_consume_end(our_version, 2 as libc::c_int as size_t);
        if r != 0 as libc::c_int {
            oerrno = *libc::__errno_location();
            crate::log::sshlog(
                b"kex.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"kex_exchange_identification\0",
                ))
                .as_ptr(),
                1311 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"sshbuf_consume_end\0" as *const u8 as *const libc::c_char,
            );
        } else {
            our_version_string = crate::sshbuf_misc::sshbuf_dup_string(our_version);
            if our_version_string.is_null() {
                crate::log::sshlog(
                    b"kex.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                        b"kex_exchange_identification\0",
                    ))
                    .as_ptr(),
                    1316 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"crate::sshbuf_misc::sshbuf_dup_string failed\0" as *const u8 as *const libc::c_char,
                );
                r = -(2 as libc::c_int);
            } else {
                crate::log::sshlog(
                    b"kex.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                        b"kex_exchange_identification\0",
                    ))
                    .as_ptr(),
                    1320 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"Local version string %.100s\0" as *const u8 as *const libc::c_char,
                    our_version_string,
                );
                n = 0 as libc::c_int as size_t;
                's_97: loop {
                    if n >= 1024 as libc::c_int as libc::c_ulong {
                        send_error(
                            ssh,
                            b"No SSH identification string received.\0" as *const u8
                                as *const libc::c_char
                                as *mut libc::c_char,
                        );
                        crate::log::sshlog(
                            b"kex.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                b"kex_exchange_identification\0",
                            ))
                            .as_ptr(),
                            1328 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"No SSH version received in first %u lines from server\0" as *const u8
                                as *const libc::c_char,
                            1024 as libc::c_int,
                        );
                        r = -(4 as libc::c_int);
                        current_block = 4276536258050058664;
                        break;
                    } else {
                        sshbuf_reset(peer_version);
                        expect_nl = 0 as libc::c_int;
                        loop {
                            if timeout_ms > 0 as libc::c_int {
                                r = waitrfd(ssh_packet_get_connection_in(ssh), &mut timeout_ms);
                                if r == -(1 as libc::c_int)
                                    && *libc::__errno_location() == 110 as libc::c_int
                                {
                                    send_error(
                                        ssh,
                                        b"Timed out waiting for SSH identification string.\0"
                                            as *const u8
                                            as *const libc::c_char
                                            as *mut libc::c_char,
                                    );
                                    crate::log::sshlog(
                                        b"kex.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                            b"kex_exchange_identification\0",
                                        ))
                                        .as_ptr(),
                                        1342 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"Connection timed out during banner exchange\0"
                                            as *const u8
                                            as *const libc::c_char,
                                    );
                                    r = -(53 as libc::c_int);
                                    current_block = 4276536258050058664;
                                    break 's_97;
                                } else if r == -(1 as libc::c_int) {
                                    oerrno = *libc::__errno_location();
                                    crate::log::sshlog(
                                        b"kex.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                            b"kex_exchange_identification\0",
                                        ))
                                        .as_ptr(),
                                        1347 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"%s\0" as *const u8 as *const libc::c_char,
                                        libc::strerror(*libc::__errno_location()),
                                    );
                                    r = -(24 as libc::c_int);
                                    current_block = 4276536258050058664;
                                    break 's_97;
                                }
                            }
                            len = atomicio(
                                Some(
                                    read as unsafe extern "C" fn(
                                        libc::c_int,
                                        *mut libc::c_void,
                                        size_t,
                                    )
                                        -> ssize_t,
                                ),
                                ssh_packet_get_connection_in(ssh),
                                &mut c as *mut u_char as *mut libc::c_void,
                                1 as libc::c_int as size_t,
                            );
                            if len != 1 as libc::c_int as libc::c_ulong
                                && *libc::__errno_location() == 32 as libc::c_int
                            {
                                crate::log::sshlog(
                                    b"kex.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                        b"kex_exchange_identification\0",
                                    ))
                                    .as_ptr(),
                                    1356 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"Connection closed by remote host\0" as *const u8
                                        as *const libc::c_char,
                                );
                                r = -(52 as libc::c_int);
                                current_block = 4276536258050058664;
                                break 's_97;
                            } else if len != 1 as libc::c_int as libc::c_ulong {
                                oerrno = *libc::__errno_location();
                                crate::log::sshlog(
                                    b"kex.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                        b"kex_exchange_identification\0",
                                    ))
                                    .as_ptr(),
                                    1361 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"read: %.100s\0" as *const u8 as *const libc::c_char,
                                    libc::strerror(*libc::__errno_location()),
                                );
                                r = -(24 as libc::c_int);
                                current_block = 4276536258050058664;
                                break 's_97;
                            } else if c as libc::c_int == '\r' as i32 {
                                expect_nl = 1 as libc::c_int;
                            } else {
                                if c as libc::c_int == '\n' as i32 {
                                    break;
                                }
                                if c as libc::c_int == '\0' as i32 || expect_nl != 0 {
                                    crate::log::sshlog(
                                        b"kex.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                            b"kex_exchange_identification\0",
                                        ))
                                        .as_ptr(),
                                        1373 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"banner line contains invalid characters\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                    current_block = 14036831669631104504;
                                    break 's_97;
                                } else {
                                    r = crate::sshbuf_getput_basic::sshbuf_put_u8(peer_version, c);
                                    if r != 0 as libc::c_int {
                                        oerrno = *libc::__errno_location();
                                        crate::log::sshlog(
                                            b"kex.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 28],
                                                &[libc::c_char; 28],
                                            >(
                                                b"kex_exchange_identification\0"
                                            ))
                                            .as_ptr(),
                                            1378 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            ssh_err(r),
                                            b"sshbuf_put\0" as *const u8 as *const libc::c_char,
                                        );
                                        current_block = 4276536258050058664;
                                        break 's_97;
                                    } else {
                                        if !(sshbuf_len(peer_version)
                                            > 8192 as libc::c_int as libc::c_ulong)
                                        {
                                            continue;
                                        }
                                        crate::log::sshlog(
                                            b"kex.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 28],
                                                &[libc::c_char; 28],
                                            >(
                                                b"kex_exchange_identification\0"
                                            ))
                                            .as_ptr(),
                                            1382 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"banner line too long\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        current_block = 14036831669631104504;
                                        break 's_97;
                                    }
                                }
                            }
                        }
                        if sshbuf_len(peer_version) > 4 as libc::c_int as libc::c_ulong
                            && memcmp(
                                sshbuf_ptr(peer_version) as *const libc::c_void,
                                b"SSH-\0" as *const u8 as *const libc::c_char
                                    as *const libc::c_void,
                                4 as libc::c_int as libc::c_ulong,
                            ) == 0 as libc::c_int
                        {
                            current_block = 9859671972921157070;
                            break;
                        }
                        cp = crate::sshbuf_misc::sshbuf_dup_string(peer_version);
                        if cp.is_null() {
                            crate::log::sshlog(
                                b"kex.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                    b"kex_exchange_identification\0",
                                ))
                                .as_ptr(),
                                1392 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"crate::sshbuf_misc::sshbuf_dup_string failed\0" as *const u8 as *const libc::c_char,
                            );
                            r = -(2 as libc::c_int);
                            current_block = 4276536258050058664;
                            break;
                        } else if (*(*ssh).kex).server != 0 {
                            crate::log::sshlog(
                                b"kex.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                    b"kex_exchange_identification\0",
                                ))
                                .as_ptr(),
                                1399 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"client sent invalid protocol identifier \"%.256s\"\0" as *const u8
                                    as *const libc::c_char,
                                cp,
                            );
                            libc::free(cp as *mut libc::c_void);
                            current_block = 14036831669631104504;
                            break;
                        } else {
                            crate::log::sshlog(
                                b"kex.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                    b"kex_exchange_identification\0",
                                ))
                                .as_ptr(),
                                1403 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG1,
                                0 as *const libc::c_char,
                                b"banner line %zu: %s\0" as *const u8 as *const libc::c_char,
                                n,
                                cp,
                            );
                            libc::free(cp as *mut libc::c_void);
                            n = n.wrapping_add(1);
                            n;
                        }
                    }
                }
                match current_block {
                    4276536258050058664 => {}
                    _ => {
                        match current_block {
                            9859671972921157070 => {
                                peer_version_string = crate::sshbuf_misc::sshbuf_dup_string(peer_version);
                                if peer_version_string.is_null() {
                                    sshfatal(
                                        b"kex.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                            b"kex_exchange_identification\0",
                                        ))
                                        .as_ptr(),
                                        1408 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_FATAL,
                                        0 as *const libc::c_char,
                                        b"crate::sshbuf_misc::sshbuf_dup_string failed\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                }
                                remote_version = calloc(
                                    1 as libc::c_int as libc::c_ulong,
                                    sshbuf_len(peer_version),
                                )
                                    as *mut libc::c_char;
                                if remote_version.is_null() {
                                    crate::log::sshlog(
                                        b"kex.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                            b"kex_exchange_identification\0",
                                        ))
                                        .as_ptr(),
                                        1411 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"calloc failed\0" as *const u8 as *const libc::c_char,
                                    );
                                    r = -(2 as libc::c_int);
                                    current_block = 4276536258050058664;
                                } else if sscanf(
                                    peer_version_string,
                                    b"SSH-%d.%d-%[^\n]\n\0" as *const u8 as *const libc::c_char,
                                    &mut remote_major as *mut libc::c_int,
                                    &mut remote_minor as *mut libc::c_int,
                                    remote_version,
                                ) != 3 as libc::c_int
                                {
                                    crate::log::sshlog(
                                        b"kex.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                                            b"kex_exchange_identification\0",
                                        ))
                                        .as_ptr(),
                                        1423 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"Bad remote protocol version identification: '%.100s'\0"
                                            as *const u8
                                            as *const libc::c_char,
                                        peer_version_string,
                                    );
                                    current_block = 14036831669631104504;
                                } else {
                                    crate::log::sshlog(
                                        b"kex.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<
                                            &[u8; 28],
                                            &[libc::c_char; 28],
                                        >(b"kex_exchange_identification\0"))
                                            .as_ptr(),
                                        1430 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG1,
                                        0 as *const libc::c_char,
                                        b"Remote protocol version %d.%d, remote software version %.100s\0"
                                            as *const u8 as *const libc::c_char,
                                        remote_major,
                                        remote_minor,
                                        remote_version,
                                    );
                                    compat_banner(ssh, remote_version);
                                    mismatch = 0 as libc::c_int;
                                    match remote_major {
                                        2 => {}
                                        1 => {
                                            if remote_minor != 99 as libc::c_int {
                                                mismatch = 1 as libc::c_int;
                                            }
                                        }
                                        _ => {
                                            mismatch = 1 as libc::c_int;
                                        }
                                    }
                                    if mismatch != 0 {
                                        crate::log::sshlog(
                                            b"kex.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 28],
                                                &[libc::c_char; 28],
                                            >(
                                                b"kex_exchange_identification\0"
                                            ))
                                            .as_ptr(),
                                            1447 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"Protocol major versions differ: %d vs. %d\0"
                                                as *const u8
                                                as *const libc::c_char,
                                            2 as libc::c_int,
                                            remote_major,
                                        );
                                        send_error(
                                            ssh,
                                            b"Protocol major versions differ.\0" as *const u8
                                                as *const libc::c_char
                                                as *mut libc::c_char,
                                        );
                                        r = -(38 as libc::c_int);
                                    } else if (*(*ssh).kex).server != 0
                                        && (*ssh).compat & 0x400000 as libc::c_int
                                            != 0 as libc::c_int
                                    {
                                        crate::log::sshlog(
                                            b"kex.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 28],
                                                &[libc::c_char; 28],
                                            >(
                                                b"kex_exchange_identification\0"
                                            ))
                                            .as_ptr(),
                                            1456 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_INFO,
                                            0 as *const libc::c_char,
                                            b"probed from %s port %d with %s.  Don't panic.\0"
                                                as *const u8
                                                as *const libc::c_char,
                                            ssh_remote_ipaddr(ssh),
                                            ssh_remote_port(ssh),
                                            peer_version_string,
                                        );
                                        r = -(52 as libc::c_int);
                                    } else if (*(*ssh).kex).server != 0
                                        && (*ssh).compat & 0x800 as libc::c_int != 0 as libc::c_int
                                    {
                                        crate::log::sshlog(
                                            b"kex.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 28],
                                                &[libc::c_char; 28],
                                            >(
                                                b"kex_exchange_identification\0"
                                            ))
                                            .as_ptr(),
                                            1463 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_INFO,
                                            0 as *const libc::c_char,
                                            b"scanned from %s port %d with %s.  Don't panic.\0"
                                                as *const u8
                                                as *const libc::c_char,
                                            ssh_remote_ipaddr(ssh),
                                            ssh_remote_port(ssh),
                                            peer_version_string,
                                        );
                                        r = -(52 as libc::c_int);
                                    } else {
                                        r = 0 as libc::c_int;
                                    }
                                    current_block = 4276536258050058664;
                                }
                            }
                            _ => {}
                        }
                        match current_block {
                            4276536258050058664 => {}
                            _ => {
                                send_error(
                                    ssh,
                                    b"Invalid SSH identification string.\0" as *const u8
                                        as *const libc::c_char
                                        as *mut libc::c_char,
                                );
                                r = -(4 as libc::c_int);
                            }
                        }
                    }
                }
            }
        }
    }
    libc::free(our_version_string as *mut libc::c_void);
    libc::free(peer_version_string as *mut libc::c_void);
    libc::free(remote_version as *mut libc::c_void);
    if r == -(24 as libc::c_int) {
        *libc::__errno_location() = oerrno;
    }
    return r;
}
