use crate::kex::dh_st;
use crate::kex::kex;
use crate::packet::key_entry;

use crate::packet::ssh;

use ::libc;
extern "C" {

    pub type ec_group_st;

    pub type bignum_st;

    fn BN_num_bits(a: *const BIGNUM) -> libc::c_int;
    fn BN_clear_free(a: *mut BIGNUM);
    fn DH_get0_key(dh: *const DH, pub_key: *mut *const BIGNUM, priv_key: *mut *const BIGNUM);
    fn DH_get0_pqg(
        dh: *const DH,
        p: *mut *const BIGNUM,
        q: *mut *const BIGNUM,
        g: *mut *const BIGNUM,
    );
    fn DH_free(dh: *mut DH);
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);

    fn sshkey_fromb(
        _: *mut crate::sshbuf::sshbuf,
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
    fn kex_verify_host_key(_: *mut ssh, _: *mut crate::sshkey::sshkey) -> libc::c_int;
    fn kex_protocol_error(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn kex_derive_keys(
        _: *mut ssh,
        _: *mut u_char,
        _: u_int,
        _: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn kex_send_newkeys(_: *mut ssh) -> libc::c_int;
    fn kex_dh_compute_key(
        _: *mut kex,
        _: *mut BIGNUM,
        _: *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn kexgex_hash(
        _: libc::c_int,
        _: *const crate::sshbuf::sshbuf,
        _: *const crate::sshbuf::sshbuf,
        _: *const crate::sshbuf::sshbuf,
        _: *const crate::sshbuf::sshbuf,
        _: *const crate::sshbuf::sshbuf,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: *const BIGNUM,
        _: *const BIGNUM,
        _: *const BIGNUM,
        _: *const BIGNUM,
        _: *const u_char,
        _: size_t,
        _: *mut u_char,
        _: *mut size_t,
    ) -> libc::c_int;

    fn sshpkt_put_bignum2(ssh: *mut ssh, v: *const BIGNUM) -> libc::c_int;

    fn sshpkt_getb_froms(ssh: *mut ssh, valp: *mut *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshpkt_get_bignum2(ssh: *mut ssh, valp: *mut *mut BIGNUM) -> libc::c_int;

    fn dh_new_group(_: *mut BIGNUM, _: *mut BIGNUM) -> *mut DH;
    fn dh_gen_key(_: *mut DH, _: libc::c_int) -> libc::c_int;
    fn dh_estimate(_: libc::c_int) -> u_int;

    fn sshbuf_fromb(buf: *mut crate::sshbuf::sshbuf) -> *mut crate::sshbuf::sshbuf;

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

pub type BIGNUM = bignum_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_sig_details {
    pub sk_counter: uint32_t,
    pub sk_flags: uint8_t,
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
pub unsafe extern "C" fn kexgex_client(mut ssh: *mut ssh) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    let mut r: libc::c_int = 0;
    let mut nbits: u_int = 0;
    nbits =
        dh_estimate(((*kex).dh_need).wrapping_mul(8 as libc::c_int as libc::c_uint) as libc::c_int);
    (*kex).min = 2048 as libc::c_int as u_int;
    (*kex).max = 8192 as libc::c_int as u_int;
    (*kex).nbits = nbits;
    if (*ssh).compat & 0x40000000 as libc::c_int != 0 {
        (*kex).nbits = if (*kex).nbits < 4096 as libc::c_int as libc::c_uint {
            (*kex).nbits
        } else {
            4096 as libc::c_int as libc::c_uint
        };
    }
    r = crate::packet::sshpkt_start(ssh, 34 as libc::c_int as u_char);
    if !(r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_put_u32(ssh, (*kex).min);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_put_u32(ssh, (*kex).nbits);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_put_u32(ssh, (*kex).max);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_send(ssh);
            r != 0 as libc::c_int
        })
    {
        crate::log::sshlog(
            b"kexgexc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"kexgex_client\0"))
                .as_ptr(),
            81 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"SSH2_MSG_KEX_DH_GEX_REQUEST(%u<%u<%u) sent\0" as *const u8 as *const libc::c_char,
            (*kex).min,
            (*kex).nbits,
            (*kex).max,
        );
        crate::log::sshlog(
            b"kexgexc.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"kexgex_client\0"))
                .as_ptr(),
            86 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"expecting SSH2_MSG_KEX_DH_GEX_GROUP\0" as *const u8 as *const libc::c_char,
        );
        crate::dispatch::ssh_dispatch_set(
            ssh,
            31 as libc::c_int,
            Some(
                input_kex_dh_gex_group
                    as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
            ),
        );
        r = 0 as libc::c_int;
    }
    return r;
}
unsafe extern "C" fn input_kex_dh_gex_group(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    let mut p: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut g: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut pub_key: *const BIGNUM = 0 as *const BIGNUM;
    let mut r: libc::c_int = 0;
    let mut bits: libc::c_int = 0;
    crate::log::sshlog(
        b"kexgexc.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"input_kex_dh_gex_group\0"))
            .as_ptr(),
        102 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"SSH2_MSG_KEX_DH_GEX_GROUP received\0" as *const u8 as *const libc::c_char,
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        31 as libc::c_int,
        Some(
            kex_protocol_error
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    r = sshpkt_get_bignum2(ssh, &mut p);
    if !(r != 0 as libc::c_int
        || {
            r = sshpkt_get_bignum2(ssh, &mut g);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        })
    {
        bits = BN_num_bits(p);
        if bits < 0 as libc::c_int || (bits as u_int) < (*kex).min || bits as u_int > (*kex).max {
            r = -(28 as libc::c_int);
        } else {
            (*kex).dh = dh_new_group(g, p);
            if ((*kex).dh).is_null() {
                r = -(2 as libc::c_int);
            } else {
                g = 0 as *mut BIGNUM;
                p = g;
                r = dh_gen_key(
                    (*kex).dh,
                    ((*kex).we_need).wrapping_mul(8 as libc::c_int as libc::c_uint) as libc::c_int,
                );
                if !(r != 0 as libc::c_int) {
                    DH_get0_key((*kex).dh, &mut pub_key, 0 as *mut *const BIGNUM);
                    r = crate::packet::sshpkt_start(ssh, 32 as libc::c_int as u_char);
                    if !(r != 0 as libc::c_int
                        || {
                            r = sshpkt_put_bignum2(ssh, pub_key);
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::packet::sshpkt_send(ssh);
                            r != 0 as libc::c_int
                        })
                    {
                        crate::log::sshlog(
                            b"kexgexc.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                                b"input_kex_dh_gex_group\0",
                            ))
                            .as_ptr(),
                            128 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"SSH2_MSG_KEX_DH_GEX_INIT sent\0" as *const u8 as *const libc::c_char,
                        );
                        crate::log::sshlog(
                            b"kexgexc.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                                b"input_kex_dh_gex_group\0",
                            ))
                            .as_ptr(),
                            135 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"expecting SSH2_MSG_KEX_DH_GEX_REPLY\0" as *const u8
                                as *const libc::c_char,
                        );
                        crate::dispatch::ssh_dispatch_set(
                            ssh,
                            33 as libc::c_int,
                            Some(
                                input_kex_dh_gex_reply
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
    BN_clear_free(p);
    BN_clear_free(g);
    return r;
}
unsafe extern "C" fn input_kex_dh_gex_reply(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    let mut dh_server_pub: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut pub_key: *const BIGNUM = 0 as *const BIGNUM;
    let mut dh_p: *const BIGNUM = 0 as *const BIGNUM;
    let mut dh_g: *const BIGNUM = 0 as *const BIGNUM;
    let mut shared_secret: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut tmp: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut server_host_key_blob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut server_host_key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut signature: *mut u_char = 0 as *mut u_char;
    let mut hash: [u_char; 64] = [0; 64];
    let mut slen: size_t = 0;
    let mut hashlen: size_t = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"kexgexc.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"input_kex_dh_gex_reply\0"))
            .as_ptr(),
        158 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"SSH2_MSG_KEX_DH_GEX_REPLY received\0" as *const u8 as *const libc::c_char,
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        33 as libc::c_int,
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
            if !(r != 0 as libc::c_int || {
                r = kex_verify_host_key(ssh, server_host_key);
                r != 0 as libc::c_int
            }) {
                r = sshpkt_get_bignum2(ssh, &mut dh_server_pub);
                if !(r != 0 as libc::c_int
                    || {
                        r = crate::packet::sshpkt_get_string(ssh, &mut signature, &mut slen);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = crate::packet::sshpkt_get_end(ssh);
                        r != 0 as libc::c_int
                    })
                {
                    shared_secret = crate::sshbuf::sshbuf_new();
                    if shared_secret.is_null() {
                        r = -(2 as libc::c_int);
                    } else {
                        r = kex_dh_compute_key(kex, dh_server_pub, shared_secret);
                        if !(r != 0 as libc::c_int) {
                            if (*ssh).compat & 0x4000 as libc::c_int != 0 {
                                (*kex).max = -(1 as libc::c_int) as u_int;
                                (*kex).min = (*kex).max;
                            }
                            DH_get0_key((*kex).dh, &mut pub_key, 0 as *mut *const BIGNUM);
                            DH_get0_pqg((*kex).dh, &mut dh_p, 0 as *mut *const BIGNUM, &mut dh_g);
                            hashlen = ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong;
                            r = kexgex_hash(
                                (*kex).hash_alg,
                                (*kex).client_version,
                                (*kex).server_version,
                                (*kex).my,
                                (*kex).peer,
                                server_host_key_blob,
                                (*kex).min as libc::c_int,
                                (*kex).nbits as libc::c_int,
                                (*kex).max as libc::c_int,
                                dh_p,
                                dh_g,
                                pub_key,
                                dh_server_pub,
                                crate::sshbuf::sshbuf_ptr(shared_secret),
                                crate::sshbuf::sshbuf_len(shared_secret),
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
                                                    r = crate::sshbuf_getput_basic::sshbuf_put(
                                                        (*kex).initial_sig,
                                                        signature as *const libc::c_void,
                                                        slen,
                                                    );
                                                    if !(r != 0 as libc::c_int) {
                                                        (*kex).initial_hostkey = server_host_key;
                                                        server_host_key =
                                                            0 as *mut crate::sshkey::sshkey;
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
    DH_free((*kex).dh);
    (*kex).dh = 0 as *mut DH;
    BN_clear_free(dh_server_pub);
    crate::sshbuf::sshbuf_free(shared_secret);
    crate::sshkey::sshkey_free(server_host_key);
    crate::sshbuf::sshbuf_free(tmp);
    crate::sshbuf::sshbuf_free(server_host_key_blob);
    libc::free(signature as *mut libc::c_void);
    return r;
}
