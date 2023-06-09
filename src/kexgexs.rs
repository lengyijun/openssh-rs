use crate::kex::dh_st;
use crate::kex::kex;
use crate::packet::key_entry;
use crate::sshbuf_getput_crypto::BIGNUM;

use crate::packet::ssh;

use ::libc;
extern "C" {

    pub type ec_group_st;

    pub type bignum_st;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);

    fn DH_get0_key(dh: *const DH, pub_key: *mut *const BIGNUM, priv_key: *mut *const BIGNUM);
    fn DH_get0_pqg(
        dh: *const DH,
        p: *mut *const BIGNUM,
        q: *mut *const BIGNUM,
        g: *mut *const BIGNUM,
    );
    fn DH_free(dh: *mut DH);
    fn BN_clear_free(a: *mut BIGNUM);

    fn sshkey_putb(_: *const crate::sshkey::sshkey, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn kex_load_hostkey(
        _: *mut ssh,
        _: *mut *mut crate::sshkey::sshkey,
        _: *mut *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
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

    fn sshpkt_disconnect(_: *mut ssh, fmt: *const libc::c_char, _: ...) -> libc::c_int;
    fn sshpkt_put_string(ssh: *mut ssh, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshpkt_put_bignum2(ssh: *mut ssh, v: *const BIGNUM) -> libc::c_int;
    fn sshpkt_put_stringb(ssh: *mut ssh, v: *const crate::sshbuf::sshbuf) -> libc::c_int;

    fn sshpkt_get_bignum2(ssh: *mut ssh, valp: *mut *mut BIGNUM) -> libc::c_int;

    fn choose_dh(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> *mut DH;
    fn dh_gen_key(_: *mut DH, _: libc::c_int) -> libc::c_int;
    static mut use_privsep: libc::c_int;
    fn mm_choose_dh(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> *mut DH;

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
pub unsafe extern "C" fn kexgex_server(mut ssh: *mut ssh) -> libc::c_int {
    crate::dispatch::ssh_dispatch_set(
        ssh,
        34 as libc::c_int,
        Some(
            input_kex_dh_gex_request
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    crate::log::sshlog(
        b"kexgexs.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"kexgex_server\0")).as_ptr(),
        66 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"expecting SSH2_MSG_KEX_DH_GEX_REQUEST\0" as *const u8 as *const libc::c_char,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn input_kex_dh_gex_request(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    let mut r: libc::c_int = 0;
    let mut min: u_int = 0 as libc::c_int as u_int;
    let mut max: u_int = 0 as libc::c_int as u_int;
    let mut nbits: u_int = 0 as libc::c_int as u_int;
    let mut dh_p: *const BIGNUM = 0 as *const BIGNUM;
    let mut dh_g: *const BIGNUM = 0 as *const BIGNUM;
    crate::log::sshlog(
        b"kexgexs.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"input_kex_dh_gex_request\0"))
            .as_ptr(),
        78 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"SSH2_MSG_KEX_DH_GEX_REQUEST received\0" as *const u8 as *const libc::c_char,
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        34 as libc::c_int,
        Some(
            kex_protocol_error
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    r = crate::packet::sshpkt_get_u32(ssh, &mut min);
    if !(r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_get_u32(ssh, &mut nbits);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_u32(ssh, &mut max);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        })
    {
        (*kex).nbits = nbits;
        (*kex).min = min;
        (*kex).max = max;
        min = if 2048 as libc::c_int as libc::c_uint > min {
            2048 as libc::c_int as libc::c_uint
        } else {
            min
        };
        max = if (8192 as libc::c_int as libc::c_uint) < max {
            8192 as libc::c_int as libc::c_uint
        } else {
            max
        };
        nbits = if 2048 as libc::c_int as libc::c_uint > nbits {
            2048 as libc::c_int as libc::c_uint
        } else {
            nbits
        };
        nbits = if (8192 as libc::c_int as libc::c_uint) < nbits {
            8192 as libc::c_int as libc::c_uint
        } else {
            nbits
        };
        if (*kex).max < (*kex).min
            || (*kex).nbits < (*kex).min
            || (*kex).max < (*kex).nbits
            || (*kex).max < 2048 as libc::c_int as libc::c_uint
        {
            r = -(28 as libc::c_int);
        } else {
            (*kex).dh = if use_privsep != 0 {
                mm_choose_dh(min as libc::c_int, nbits as libc::c_int, max as libc::c_int)
            } else {
                choose_dh(min as libc::c_int, nbits as libc::c_int, max as libc::c_int)
            };
            if ((*kex).dh).is_null() {
                sshpkt_disconnect(
                    ssh,
                    b"no matching DH grp found\0" as *const u8 as *const libc::c_char,
                );
                r = -(2 as libc::c_int);
            } else {
                crate::log::sshlog(
                    b"kexgexs.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                        b"input_kex_dh_gex_request\0",
                    ))
                    .as_ptr(),
                    107 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"SSH2_MSG_KEX_DH_GEX_GROUP sent\0" as *const u8 as *const libc::c_char,
                );
                DH_get0_pqg((*kex).dh, &mut dh_p, 0 as *mut *const BIGNUM, &mut dh_g);
                r = crate::packet::sshpkt_start(ssh, 31 as libc::c_int as u_char);
                if !(r != 0 as libc::c_int
                    || {
                        r = sshpkt_put_bignum2(ssh, dh_p);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshpkt_put_bignum2(ssh, dh_g);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = crate::packet::sshpkt_send(ssh);
                        r != 0 as libc::c_int
                    })
                {
                    r = dh_gen_key(
                        (*kex).dh,
                        ((*kex).we_need).wrapping_mul(8 as libc::c_int as libc::c_uint)
                            as libc::c_int,
                    );
                    if !(r != 0 as libc::c_int) {
                        crate::log::sshlog(
                            b"kexgexs.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"input_kex_dh_gex_request\0",
                            ))
                            .as_ptr(),
                            119 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"expecting SSH2_MSG_KEX_DH_GEX_INIT\0" as *const u8
                                as *const libc::c_char,
                        );
                        crate::dispatch::ssh_dispatch_set(
                            ssh,
                            32 as libc::c_int,
                            Some(
                                input_kex_dh_gex_init
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
    return r;
}
unsafe extern "C" fn input_kex_dh_gex_init(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut kex: *mut kex = (*ssh).kex;
    let mut dh_client_pub: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut pub_key: *const BIGNUM = 0 as *const BIGNUM;
    let mut dh_p: *const BIGNUM = 0 as *const BIGNUM;
    let mut dh_g: *const BIGNUM = 0 as *const BIGNUM;
    let mut shared_secret: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut server_host_key_blob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut server_host_public: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut server_host_private: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut signature: *mut u_char = 0 as *mut u_char;
    let mut hash: [u_char; 64] = [0; 64];
    let mut slen: size_t = 0;
    let mut hashlen: size_t = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"kexgexs.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"input_kex_dh_gex_init\0"))
            .as_ptr(),
        140 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"SSH2_MSG_KEX_DH_GEX_INIT received\0" as *const u8 as *const libc::c_char,
    );
    crate::dispatch::ssh_dispatch_set(
        ssh,
        32 as libc::c_int,
        Some(
            kex_protocol_error
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    r = kex_load_hostkey(ssh, &mut server_host_private, &mut server_host_public);
    if !(r != 0 as libc::c_int) {
        r = sshpkt_get_bignum2(ssh, &mut dh_client_pub);
        if !(r != 0 as libc::c_int || {
            r = crate::packet::sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }) {
            shared_secret = crate::sshbuf::sshbuf_new();
            if shared_secret.is_null() {
                r = -(2 as libc::c_int);
            } else {
                r = kex_dh_compute_key(kex, dh_client_pub, shared_secret);
                if !(r != 0 as libc::c_int) {
                    server_host_key_blob = crate::sshbuf::sshbuf_new();
                    if server_host_key_blob.is_null() {
                        r = -(2 as libc::c_int);
                    } else {
                        r = sshkey_putb(server_host_public, server_host_key_blob);
                        if !(r != 0 as libc::c_int) {
                            DH_get0_key((*kex).dh, &mut pub_key, 0 as *mut *const BIGNUM);
                            DH_get0_pqg((*kex).dh, &mut dh_p, 0 as *mut *const BIGNUM, &mut dh_g);
                            hashlen = ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong;
                            r = kexgex_hash(
                                (*kex).hash_alg,
                                (*kex).client_version,
                                (*kex).server_version,
                                (*kex).peer,
                                (*kex).my,
                                server_host_key_blob,
                                (*kex).min as libc::c_int,
                                (*kex).nbits as libc::c_int,
                                (*kex).max as libc::c_int,
                                dh_p,
                                dh_g,
                                dh_client_pub,
                                pub_key,
                                crate::sshbuf::sshbuf_ptr(shared_secret),
                                crate::sshbuf::sshbuf_len(shared_secret),
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
                                if !(r < 0 as libc::c_int) {
                                    r = crate::packet::sshpkt_start(
                                        ssh,
                                        33 as libc::c_int as u_char,
                                    );
                                    if !(r != 0 as libc::c_int
                                        || {
                                            r = sshpkt_put_stringb(ssh, server_host_key_blob);
                                            r != 0 as libc::c_int
                                        }
                                        || {
                                            r = sshpkt_put_bignum2(ssh, pub_key);
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
                                            r = crate::packet::sshpkt_send(ssh);
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
                                                r = crate::sshkey::sshkey_from_private(
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
    }
    explicit_bzero(
        hash.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    DH_free((*kex).dh);
    (*kex).dh = 0 as *mut DH;
    BN_clear_free(dh_client_pub);
    crate::sshbuf::sshbuf_free(shared_secret);
    crate::sshbuf::sshbuf_free(server_host_key_blob);
    libc::free(signature as *mut libc::c_void);
    return r;
}
