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
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);

    fn sshkey_verify(
        _: *const sshkey,
        _: *const u_char,
        _: size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: u_int,
        _: *mut *mut sshkey_sig_details,
    ) -> libc::c_int;
    fn sshkey_putb(_: *const sshkey, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshkey_fromb(_: *mut crate::sshbuf::sshbuf, _: *mut *mut sshkey) -> libc::c_int;
    fn sshkey_from_private(_: *const sshkey, _: *mut *mut sshkey) -> libc::c_int;
    fn sshkey_free(_: *mut sshkey);
    fn kex_verify_host_key(_: *mut ssh, _: *mut sshkey) -> libc::c_int;
    fn kex_load_hostkey(_: *mut ssh, _: *mut *mut sshkey, _: *mut *mut sshkey) -> libc::c_int;
    fn kex_c25519_dec(
        _: *mut kex,
        _: *const crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn kex_c25519_enc(
        _: *mut kex,
        _: *const crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn kex_protocol_error(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn kex_derive_keys(
        _: *mut ssh,
        _: *mut u_char,
        _: u_int,
        _: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn kex_send_newkeys(_: *mut ssh) -> libc::c_int;
    fn kex_dh_keypair(_: *mut kex) -> libc::c_int;
    fn kex_ecdh_keypair(_: *mut kex) -> libc::c_int;
    fn kex_c25519_keypair(_: *mut kex) -> libc::c_int;
    fn kex_dh_enc(
        _: *mut kex,
        _: *const crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn kex_dh_dec(
        _: *mut kex,
        _: *const crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn kex_ecdh_enc(
        _: *mut kex,
        _: *const crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn kex_ecdh_dec(
        _: *mut kex,
        _: *const crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn kex_kem_sntrup761x25519_keypair(_: *mut kex) -> libc::c_int;
    fn kex_kem_sntrup761x25519_enc(
        _: *mut kex,
        _: *const crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn kex_kem_sntrup761x25519_dec(
        _: *mut kex,
        _: *const crate::sshbuf::sshbuf,
        _: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;

    fn sshpkt_start(ssh: *mut ssh, type_0: u_char) -> libc::c_int;
    fn sshpkt_send(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_get_end(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_put_string(ssh: *mut ssh, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshpkt_put_stringb(ssh: *mut ssh, v: *const crate::sshbuf::sshbuf) -> libc::c_int;
    fn ssh_dispatch_set(_: *mut ssh, _: libc::c_int, _: Option<dispatch_fn>);
    fn sshpkt_getb_froms(ssh: *mut ssh, valp: *mut *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshpkt_get_string(ssh: *mut ssh, valp: *mut *mut u_char, lenp: *mut size_t) -> libc::c_int;

    fn sshbuf_fromb(buf: *mut crate::sshbuf::sshbuf) -> *mut crate::sshbuf::sshbuf;

    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_putb(buf: *mut crate::sshbuf::sshbuf, v: *const crate::sshbuf::sshbuf)
        -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut crate::sshbuf::sshbuf, val: u_int32_t) -> libc::c_int;

    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn ssh_digest_bytes(alg: libc::c_int) -> size_t;
    fn ssh_digest_buffer(
        alg: libc::c_int,
        b: *const crate::sshbuf::sshbuf,
        d: *mut u_char,
        dlen: size_t,
    ) -> libc::c_int;
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
pub type uint32_t = __uint32_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_sig_details {
    pub sk_counter: uint32_t,
    pub sk_flags: uint8_t,
}
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
unsafe extern "C" fn kex_gen_hash(
    mut hash_alg: libc::c_int,
    mut client_version: *const crate::sshbuf::sshbuf,
    mut server_version: *const crate::sshbuf::sshbuf,
    mut client_kexinit: *const crate::sshbuf::sshbuf,
    mut server_kexinit: *const crate::sshbuf::sshbuf,
    mut server_host_key_blob: *const crate::sshbuf::sshbuf,
    mut client_pub: *const crate::sshbuf::sshbuf,
    mut server_pub: *const crate::sshbuf::sshbuf,
    mut shared_secret: *const crate::sshbuf::sshbuf,
    mut hash: *mut u_char,
    mut hashlen: *mut size_t,
) -> libc::c_int {
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    if *hashlen < ssh_digest_bytes(hash_alg) {
        return -(10 as libc::c_int);
    }
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_put_stringb(b, client_version);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_stringb(b, server_version);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(
                b,
                (crate::sshbuf::sshbuf_len(client_kexinit))
                    .wrapping_add(1 as libc::c_int as libc::c_ulong) as u_int32_t,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(b, 20 as libc::c_int as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_putb(b, client_kexinit);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(
                b,
                (crate::sshbuf::sshbuf_len(server_kexinit))
                    .wrapping_add(1 as libc::c_int as libc::c_ulong) as u_int32_t,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(b, 20 as libc::c_int as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_putb(b, server_kexinit);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(b, server_host_key_blob);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(b, client_pub);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(b, server_pub);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_putb(b, shared_secret);
            r != 0 as libc::c_int
        }
    {
        crate::sshbuf::sshbuf_free(b);
        return r;
    }
    if ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0 as libc::c_int {
        crate::sshbuf::sshbuf_free(b);
        return -(22 as libc::c_int);
    }
    crate::sshbuf::sshbuf_free(b);
    *hashlen = ssh_digest_bytes(hash_alg);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn kex_gen_client(mut ssh: *mut ssh) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    let mut r: libc::c_int = 0;
    match (*kex).kex_type {
        0 | 1 | 2 | 3 | 4 => {
            r = kex_dh_keypair(kex);
        }
        7 => {
            r = kex_ecdh_keypair(kex);
        }
        8 => {
            r = kex_c25519_keypair(kex);
        }
        9 => {
            r = kex_kem_sntrup761x25519_keypair(kex);
        }
        _ => {
            r = -(10 as libc::c_int);
        }
    }
    if r != 0 as libc::c_int {
        return r;
    }
    r = sshpkt_start(ssh, 30 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_stringb(ssh, (*kex).client_pub);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    crate::log::sshlog(
        b"kexgen.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"kex_gen_client\0")).as_ptr(),
        133 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"expecting SSH2_MSG_KEX_ECDH_REPLY\0" as *const u8 as *const libc::c_char,
    );
    ssh_dispatch_set(
        ssh,
        31 as libc::c_int,
        Some(
            input_kex_gen_reply
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn input_kex_gen_reply(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    let mut server_host_key: *mut sshkey = 0 as *mut sshkey;
    let mut shared_secret: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut server_blob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut tmp: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut server_host_key_blob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut signature: *mut u_char = 0 as *mut u_char;
    let mut hash: [u_char; 64] = [0; 64];
    let mut slen: size_t = 0;
    let mut hashlen: size_t = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"kexgen.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"input_kex_gen_reply\0"))
            .as_ptr(),
        151 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"SSH2_MSG_KEX_ECDH_REPLY received\0" as *const u8 as *const libc::c_char,
    );
    ssh_dispatch_set(
        ssh,
        31 as libc::c_int,
        Some(
            kex_protocol_error
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    r = sshpkt_getb_froms(ssh, &mut server_host_key_blob);
    if !(r != 0 as libc::c_int) {
        tmp = sshbuf_fromb(server_host_key_blob);
        if tmp.is_null() {
            r = -(2 as libc::c_int);
        } else {
            r = sshkey_fromb(tmp, &mut server_host_key);
            if !(r != 0 as libc::c_int) {
                r = kex_verify_host_key(ssh, server_host_key);
                if !(r != 0 as libc::c_int) {
                    r = sshpkt_getb_froms(ssh, &mut server_blob);
                    if !(r != 0 as libc::c_int
                        || {
                            r = sshpkt_get_string(ssh, &mut signature, &mut slen);
                            r != 0 as libc::c_int
                        }
                        || {
                            r = sshpkt_get_end(ssh);
                            r != 0 as libc::c_int
                        })
                    {
                        match (*kex).kex_type {
                            0 | 1 | 2 | 3 | 4 => {
                                r = kex_dh_dec(kex, server_blob, &mut shared_secret);
                            }
                            7 => {
                                r = kex_ecdh_dec(kex, server_blob, &mut shared_secret);
                            }
                            8 => {
                                r = kex_c25519_dec(kex, server_blob, &mut shared_secret);
                            }
                            9 => {
                                r = kex_kem_sntrup761x25519_dec(
                                    kex,
                                    server_blob,
                                    &mut shared_secret,
                                );
                            }
                            _ => {
                                r = -(10 as libc::c_int);
                            }
                        }
                        if !(r != 0 as libc::c_int) {
                            hashlen = ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong;
                            r = kex_gen_hash(
                                (*kex).hash_alg,
                                (*kex).client_version,
                                (*kex).server_version,
                                (*kex).my,
                                (*kex).peer,
                                server_host_key_blob,
                                (*kex).client_pub,
                                server_blob,
                                shared_secret,
                                hash.as_mut_ptr(),
                                &mut hashlen,
                            );
                            if !(r != 0 as libc::c_int) {
                                r = sshkey_verify(
                                    server_host_key,
                                    signature,
                                    slen,
                                    hash.as_mut_ptr(),
                                    hashlen,
                                    (*kex).hostkey_alg,
                                    (*ssh).compat as u_int,
                                    0 as *mut *mut sshkey_sig_details,
                                );
                                if !(r != 0 as libc::c_int) {
                                    r = kex_derive_keys(
                                        ssh,
                                        hash.as_mut_ptr(),
                                        hashlen as u_int,
                                        shared_secret,
                                    );
                                    if !(r != 0 as libc::c_int || {
                                        r = kex_send_newkeys(ssh);
                                        r != 0 as libc::c_int
                                    }) {
                                        if (*kex).flags & 0x2 as libc::c_int as libc::c_uint
                                            != 0 as libc::c_int as libc::c_uint
                                        {
                                            if !((*kex).initial_hostkey).is_null()
                                                || !((*kex).initial_sig).is_null()
                                            {
                                                r = -(1 as libc::c_int);
                                            } else {
                                                (*kex).initial_sig = crate::sshbuf::sshbuf_new();
                                                if ((*kex).initial_sig).is_null() {
                                                    r = -(2 as libc::c_int);
                                                } else {
                                                    r = sshbuf_put(
                                                        (*kex).initial_sig,
                                                        signature as *const libc::c_void,
                                                        slen,
                                                    );
                                                    if !(r != 0 as libc::c_int) {
                                                        (*kex).initial_hostkey = server_host_key;
                                                        server_host_key = 0 as *mut sshkey;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    explicit_bzero(
        hash.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    explicit_bzero(
        ((*kex).c25519_client_key).as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 32]>() as libc::c_ulong,
    );
    explicit_bzero(
        ((*kex).sntrup761_client_key).as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 1763]>() as libc::c_ulong,
    );
    crate::sshbuf::sshbuf_free(server_host_key_blob);
    libc::free(signature as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(tmp);
    sshkey_free(server_host_key);
    crate::sshbuf::sshbuf_free(server_blob);
    crate::sshbuf::sshbuf_free(shared_secret);
    crate::sshbuf::sshbuf_free((*kex).client_pub);
    (*kex).client_pub = 0 as *mut crate::sshbuf::sshbuf;
    return r;
}
pub unsafe extern "C" fn kex_gen_server(mut ssh: *mut ssh) -> libc::c_int {
    crate::log::sshlog(
        b"kexgen.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"kex_gen_server\0")).as_ptr(),
        260 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"expecting SSH2_MSG_KEX_ECDH_INIT\0" as *const u8 as *const libc::c_char,
    );
    ssh_dispatch_set(
        ssh,
        30 as libc::c_int,
        Some(
            input_kex_gen_init
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn input_kex_gen_init(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    let mut server_host_private: *mut sshkey = 0 as *mut sshkey;
    let mut server_host_public: *mut sshkey = 0 as *mut sshkey;
    let mut shared_secret: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut server_pubkey: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut client_pubkey: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut server_host_key_blob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut signature: *mut u_char = 0 as *mut u_char;
    let mut hash: [u_char; 64] = [0; 64];
    let mut slen: size_t = 0;
    let mut hashlen: size_t = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"kexgen.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"input_kex_gen_init\0"))
            .as_ptr(),
        278 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"SSH2_MSG_KEX_ECDH_INIT received\0" as *const u8 as *const libc::c_char,
    );
    ssh_dispatch_set(
        ssh,
        30 as libc::c_int,
        Some(
            kex_protocol_error
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    r = kex_load_hostkey(ssh, &mut server_host_private, &mut server_host_public);
    if !(r != 0 as libc::c_int) {
        r = sshpkt_getb_froms(ssh, &mut client_pubkey);
        if !(r != 0 as libc::c_int || {
            r = sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }) {
            match (*kex).kex_type {
                0 | 1 | 2 | 3 | 4 => {
                    r = kex_dh_enc(kex, client_pubkey, &mut server_pubkey, &mut shared_secret);
                }
                7 => {
                    r = kex_ecdh_enc(kex, client_pubkey, &mut server_pubkey, &mut shared_secret);
                }
                8 => {
                    r = kex_c25519_enc(kex, client_pubkey, &mut server_pubkey, &mut shared_secret);
                }
                9 => {
                    r = kex_kem_sntrup761x25519_enc(
                        kex,
                        client_pubkey,
                        &mut server_pubkey,
                        &mut shared_secret,
                    );
                }
                _ => {
                    r = -(10 as libc::c_int);
                }
            }
            if !(r != 0 as libc::c_int) {
                server_host_key_blob = crate::sshbuf::sshbuf_new();
                if server_host_key_blob.is_null() {
                    r = -(2 as libc::c_int);
                } else {
                    r = sshkey_putb(server_host_public, server_host_key_blob);
                    if !(r != 0 as libc::c_int) {
                        hashlen = ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong;
                        r = kex_gen_hash(
                            (*kex).hash_alg,
                            (*kex).client_version,
                            (*kex).server_version,
                            (*kex).peer,
                            (*kex).my,
                            server_host_key_blob,
                            client_pubkey,
                            server_pubkey,
                            shared_secret,
                            hash.as_mut_ptr(),
                            &mut hashlen,
                        );
                        if !(r != 0 as libc::c_int) {
                            r = ((*kex).sign).expect("non-null function pointer")(
                                ssh,
                                server_host_private,
                                server_host_public,
                                &mut signature,
                                &mut slen,
                                hash.as_mut_ptr(),
                                hashlen,
                                (*kex).hostkey_alg,
                            );
                            if !(r != 0 as libc::c_int) {
                                r = sshpkt_start(ssh, 31 as libc::c_int as u_char);
                                if !(r != 0 as libc::c_int
                                    || {
                                        r = sshpkt_put_stringb(ssh, server_host_key_blob);
                                        r != 0 as libc::c_int
                                    }
                                    || {
                                        r = sshpkt_put_stringb(ssh, server_pubkey);
                                        r != 0 as libc::c_int
                                    }
                                    || {
                                        r = sshpkt_put_string(
                                            ssh,
                                            signature as *const libc::c_void,
                                            slen,
                                        );
                                        r != 0 as libc::c_int
                                    }
                                    || {
                                        r = sshpkt_send(ssh);
                                        r != 0 as libc::c_int
                                    })
                                {
                                    r = kex_derive_keys(
                                        ssh,
                                        hash.as_mut_ptr(),
                                        hashlen as u_int,
                                        shared_secret,
                                    );
                                    if !(r != 0 as libc::c_int || {
                                        r = kex_send_newkeys(ssh);
                                        r != 0 as libc::c_int
                                    }) {
                                        ((*kex).initial_hostkey).is_null() && {
                                            r = sshkey_from_private(
                                                server_host_public,
                                                &mut (*kex).initial_hostkey,
                                            );
                                            r != 0 as libc::c_int
                                        };
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    explicit_bzero(
        hash.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    crate::sshbuf::sshbuf_free(server_host_key_blob);
    libc::free(signature as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(shared_secret);
    crate::sshbuf::sshbuf_free(client_pubkey);
    crate::sshbuf::sshbuf_free(server_pubkey);
    return r;
}
