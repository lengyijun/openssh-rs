use ::libc;
extern "C" {
    pub type ssh_hmac_ctx;
    pub type umac_ctx;
    fn timingsafe_bcmp(_: *const libc::c_void, _: *const libc::c_void, _: size_t) -> libc::c_int;
    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;
    fn ssh_hmac_bytes(alg: libc::c_int) -> size_t;
    fn ssh_hmac_start(alg: libc::c_int) -> *mut ssh_hmac_ctx;
    fn ssh_hmac_init(ctx: *mut ssh_hmac_ctx, key: *const libc::c_void, klen: size_t)
        -> libc::c_int;
    fn ssh_hmac_update(ctx: *mut ssh_hmac_ctx, m: *const libc::c_void, mlen: size_t)
        -> libc::c_int;
    fn ssh_hmac_final(ctx: *mut ssh_hmac_ctx, d: *mut u_char, dlen: size_t) -> libc::c_int;
    fn ssh_hmac_free(ctx: *mut ssh_hmac_ctx);
    fn umac_new(key: *const u_char) -> *mut umac_ctx;
    fn umac_update(ctx: *mut umac_ctx, input: *const u_char, len: libc::c_long) -> libc::c_int;
    fn umac_final(ctx: *mut umac_ctx, tag: *mut u_char, nonce: *const u_char) -> libc::c_int;
    fn umac_delete(ctx: *mut umac_ctx) -> libc::c_int;
    fn umac128_new(key: *const u_char) -> *mut umac_ctx;
    fn umac128_update(ctx: *mut umac_ctx, input: *const u_char, len: libc::c_long) -> libc::c_int;
    fn umac128_final(ctx: *mut umac_ctx, tag: *mut u_char, nonce: *const u_char) -> libc::c_int;
    fn umac128_delete(ctx: *mut umac_ctx) -> libc::c_int;
    fn put_u64(_: *mut libc::c_void, _: u_int64_t);
    fn put_u32(_: *mut libc::c_void, _: u_int32_t);
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
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
pub struct macalg {
    pub name: *mut libc::c_char,
    pub type_0: libc::c_int,
    pub alg: libc::c_int,
    pub truncatebits: libc::c_int,
    pub key_len: libc::c_int,
    pub len: libc::c_int,
    pub etm: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub m: [u_char; 64],
    pub for_align: u_int64_t,
}
static mut macs: [macalg; 17] = [
    {
        let mut init = macalg {
            name: b"hmac-sha1\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            type_0: 1 as libc::c_int,
            alg: 1 as libc::c_int,
            truncatebits: 0 as libc::c_int,
            key_len: 0 as libc::c_int,
            len: 0 as libc::c_int,
            etm: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"hmac-sha1-96\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            type_0: 1 as libc::c_int,
            alg: 1 as libc::c_int,
            truncatebits: 96 as libc::c_int,
            key_len: 0 as libc::c_int,
            len: 0 as libc::c_int,
            etm: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"hmac-sha2-256\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            type_0: 1 as libc::c_int,
            alg: 2 as libc::c_int,
            truncatebits: 0 as libc::c_int,
            key_len: 0 as libc::c_int,
            len: 0 as libc::c_int,
            etm: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"hmac-sha2-512\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            type_0: 1 as libc::c_int,
            alg: 4 as libc::c_int,
            truncatebits: 0 as libc::c_int,
            key_len: 0 as libc::c_int,
            len: 0 as libc::c_int,
            etm: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"hmac-md5\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            type_0: 1 as libc::c_int,
            alg: 0 as libc::c_int,
            truncatebits: 0 as libc::c_int,
            key_len: 0 as libc::c_int,
            len: 0 as libc::c_int,
            etm: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"hmac-md5-96\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            type_0: 1 as libc::c_int,
            alg: 0 as libc::c_int,
            truncatebits: 96 as libc::c_int,
            key_len: 0 as libc::c_int,
            len: 0 as libc::c_int,
            etm: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"umac-64@openssh.com\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            type_0: 2 as libc::c_int,
            alg: 0 as libc::c_int,
            truncatebits: 0 as libc::c_int,
            key_len: 128 as libc::c_int,
            len: 64 as libc::c_int,
            etm: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"umac-128@openssh.com\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: 3 as libc::c_int,
            alg: 0 as libc::c_int,
            truncatebits: 0 as libc::c_int,
            key_len: 128 as libc::c_int,
            len: 128 as libc::c_int,
            etm: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"hmac-sha1-etm@openssh.com\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: 1 as libc::c_int,
            alg: 1 as libc::c_int,
            truncatebits: 0 as libc::c_int,
            key_len: 0 as libc::c_int,
            len: 0 as libc::c_int,
            etm: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"hmac-sha1-96-etm@openssh.com\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: 1 as libc::c_int,
            alg: 1 as libc::c_int,
            truncatebits: 96 as libc::c_int,
            key_len: 0 as libc::c_int,
            len: 0 as libc::c_int,
            etm: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"hmac-sha2-256-etm@openssh.com\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: 1 as libc::c_int,
            alg: 2 as libc::c_int,
            truncatebits: 0 as libc::c_int,
            key_len: 0 as libc::c_int,
            len: 0 as libc::c_int,
            etm: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"hmac-sha2-512-etm@openssh.com\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: 1 as libc::c_int,
            alg: 4 as libc::c_int,
            truncatebits: 0 as libc::c_int,
            key_len: 0 as libc::c_int,
            len: 0 as libc::c_int,
            etm: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"hmac-md5-etm@openssh.com\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: 1 as libc::c_int,
            alg: 0 as libc::c_int,
            truncatebits: 0 as libc::c_int,
            key_len: 0 as libc::c_int,
            len: 0 as libc::c_int,
            etm: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"hmac-md5-96-etm@openssh.com\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: 1 as libc::c_int,
            alg: 0 as libc::c_int,
            truncatebits: 96 as libc::c_int,
            key_len: 0 as libc::c_int,
            len: 0 as libc::c_int,
            etm: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"umac-64-etm@openssh.com\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: 2 as libc::c_int,
            alg: 0 as libc::c_int,
            truncatebits: 0 as libc::c_int,
            key_len: 128 as libc::c_int,
            len: 64 as libc::c_int,
            etm: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: b"umac-128-etm@openssh.com\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            type_0: 3 as libc::c_int,
            alg: 0 as libc::c_int,
            truncatebits: 0 as libc::c_int,
            key_len: 128 as libc::c_int,
            len: 128 as libc::c_int,
            etm: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = macalg {
            name: 0 as *const libc::c_char as *mut libc::c_char,
            type_0: 0 as libc::c_int,
            alg: 0 as libc::c_int,
            truncatebits: 0 as libc::c_int,
            key_len: 0 as libc::c_int,
            len: 0 as libc::c_int,
            etm: 0 as libc::c_int,
        };
        init
    },
];
pub unsafe extern "C" fn mac_alg_list(mut sep: libc::c_char) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut nlen: size_t = 0;
    let mut rlen: size_t = 0 as libc::c_int as size_t;
    let mut m: *const macalg = 0 as *const macalg;
    m = macs.as_ptr();
    while !((*m).name).is_null() {
        if !ret.is_null() {
            let fresh0 = rlen;
            rlen = rlen.wrapping_add(1);
            *ret.offset(fresh0 as isize) = sep;
        }
        nlen = strlen((*m).name);
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
            (*m).name as *const libc::c_void,
            nlen.wrapping_add(1 as libc::c_int as libc::c_ulong),
        );
        rlen = (rlen as libc::c_ulong).wrapping_add(nlen) as size_t as size_t;
        m = m.offset(1);
        m;
    }
    return ret;
}
unsafe extern "C" fn mac_setup_by_alg(
    mut mac: *mut sshmac,
    mut macalg: *const macalg,
) -> libc::c_int {
    (*mac).type_0 = (*macalg).type_0;
    if (*mac).type_0 == 1 as libc::c_int {
        (*mac).hmac_ctx = ssh_hmac_start((*macalg).alg);
        if ((*mac).hmac_ctx).is_null() {
            return -(2 as libc::c_int);
        }
        (*mac).mac_len = ssh_hmac_bytes((*macalg).alg) as u_int;
        (*mac).key_len = (*mac).mac_len;
    } else {
        (*mac).mac_len = ((*macalg).len / 8 as libc::c_int) as u_int;
        (*mac).key_len = ((*macalg).key_len / 8 as libc::c_int) as u_int;
        (*mac).umac_ctx = 0 as *mut umac_ctx;
    }
    if (*macalg).truncatebits != 0 as libc::c_int {
        (*mac).mac_len = ((*macalg).truncatebits / 8 as libc::c_int) as u_int;
    }
    (*mac).etm = (*macalg).etm;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn mac_setup(
    mut mac: *mut sshmac,
    mut name: *mut libc::c_char,
) -> libc::c_int {
    let mut m: *const macalg = 0 as *const macalg;
    m = macs.as_ptr();
    while !((*m).name).is_null() {
        if strcmp(name, (*m).name) != 0 as libc::c_int {
            m = m.offset(1);
            m;
        } else {
            if !mac.is_null() {
                return mac_setup_by_alg(mac, m);
            }
            return 0 as libc::c_int;
        }
    }
    return -(10 as libc::c_int);
}
pub unsafe extern "C" fn mac_init(mut mac: *mut sshmac) -> libc::c_int {
    if ((*mac).key).is_null() {
        return -(10 as libc::c_int);
    }
    match (*mac).type_0 {
        1 => {
            if ((*mac).hmac_ctx).is_null()
                || ssh_hmac_init(
                    (*mac).hmac_ctx,
                    (*mac).key as *const libc::c_void,
                    (*mac).key_len as size_t,
                ) < 0 as libc::c_int
            {
                return -(10 as libc::c_int);
            }
            return 0 as libc::c_int;
        }
        2 => {
            (*mac).umac_ctx = umac_new((*mac).key as *const u_char);
            if ((*mac).umac_ctx).is_null() {
                return -(2 as libc::c_int);
            }
            return 0 as libc::c_int;
        }
        3 => {
            (*mac).umac_ctx = umac128_new((*mac).key as *const u_char);
            if ((*mac).umac_ctx).is_null() {
                return -(2 as libc::c_int);
            }
            return 0 as libc::c_int;
        }
        _ => return -(10 as libc::c_int),
    };
}
pub unsafe extern "C" fn mac_compute(
    mut mac: *mut sshmac,
    mut seqno: u_int32_t,
    mut data: *const u_char,
    mut datalen: libc::c_int,
    mut digest: *mut u_char,
    mut dlen: size_t,
) -> libc::c_int {
    static mut u: C2RustUnnamed = C2RustUnnamed { m: [0; 64] };
    let mut b: [u_char; 4] = [0; 4];
    let mut nonce: [u_char; 8] = [0; 8];
    if (*mac).mac_len as libc::c_ulong > ::core::mem::size_of::<C2RustUnnamed>() as libc::c_ulong {
        return -(1 as libc::c_int);
    }
    match (*mac).type_0 {
        1 => {
            put_u32(b.as_mut_ptr() as *mut libc::c_void, seqno);
            if ssh_hmac_init(
                (*mac).hmac_ctx,
                0 as *const libc::c_void,
                0 as libc::c_int as size_t,
            ) < 0 as libc::c_int
                || ssh_hmac_update(
                    (*mac).hmac_ctx,
                    b.as_mut_ptr() as *const libc::c_void,
                    ::core::mem::size_of::<[u_char; 4]>() as libc::c_ulong,
                ) < 0 as libc::c_int
                || ssh_hmac_update(
                    (*mac).hmac_ctx,
                    data as *const libc::c_void,
                    datalen as size_t,
                ) < 0 as libc::c_int
                || ssh_hmac_final(
                    (*mac).hmac_ctx,
                    (u.m).as_mut_ptr(),
                    ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
                ) < 0 as libc::c_int
            {
                return -(22 as libc::c_int);
            }
        }
        2 => {
            let __v: u_int64_t = seqno as u_int64_t;
            *nonce.as_mut_ptr().offset(0 as libc::c_int as isize) =
                (__v >> 56 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
            *nonce.as_mut_ptr().offset(1 as libc::c_int as isize) =
                (__v >> 48 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
            *nonce.as_mut_ptr().offset(2 as libc::c_int as isize) =
                (__v >> 40 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
            *nonce.as_mut_ptr().offset(3 as libc::c_int as isize) =
                (__v >> 32 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
            *nonce.as_mut_ptr().offset(4 as libc::c_int as isize) =
                (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
            *nonce.as_mut_ptr().offset(5 as libc::c_int as isize) =
                (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
            *nonce.as_mut_ptr().offset(6 as libc::c_int as isize) =
                (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_ulong) as u_char;
            *nonce.as_mut_ptr().offset(7 as libc::c_int as isize) =
                (__v & 0xff as libc::c_int as libc::c_ulong) as u_char;
            umac_update((*mac).umac_ctx, data, datalen as libc::c_long);
            umac_final(
                (*mac).umac_ctx,
                (u.m).as_mut_ptr(),
                nonce.as_mut_ptr() as *const u_char,
            );
        }
        3 => {
            put_u64(nonce.as_mut_ptr() as *mut libc::c_void, seqno as u_int64_t);
            umac128_update((*mac).umac_ctx, data, datalen as libc::c_long);
            umac128_final(
                (*mac).umac_ctx,
                (u.m).as_mut_ptr(),
                nonce.as_mut_ptr() as *const u_char,
            );
        }
        _ => return -(10 as libc::c_int),
    }
    if !digest.is_null() {
        if dlen > (*mac).mac_len as libc::c_ulong {
            dlen = (*mac).mac_len as size_t;
        }
        memcpy(
            digest as *mut libc::c_void,
            (u.m).as_mut_ptr() as *const libc::c_void,
            dlen,
        );
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn mac_check(
    mut mac: *mut sshmac,
    mut seqno: u_int32_t,
    mut data: *const u_char,
    mut dlen: size_t,
    mut theirmac: *const u_char,
    mut mlen: size_t,
) -> libc::c_int {
    let mut ourmac: [u_char; 64] = [0; 64];
    let mut r: libc::c_int = 0;
    if (*mac).mac_len as libc::c_ulong > mlen {
        return -(10 as libc::c_int);
    }
    r = mac_compute(
        mac,
        seqno,
        data,
        dlen as libc::c_int,
        ourmac.as_mut_ptr(),
        ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
    );
    if r != 0 as libc::c_int {
        return r;
    }
    if timingsafe_bcmp(
        ourmac.as_mut_ptr() as *const libc::c_void,
        theirmac as *const libc::c_void,
        (*mac).mac_len as size_t,
    ) != 0 as libc::c_int
    {
        return -(30 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn mac_clear(mut mac: *mut sshmac) {
    if (*mac).type_0 == 2 as libc::c_int {
        if !((*mac).umac_ctx).is_null() {
            umac_delete((*mac).umac_ctx);
        }
    } else if (*mac).type_0 == 3 as libc::c_int {
        if !((*mac).umac_ctx).is_null() {
            umac128_delete((*mac).umac_ctx);
        }
    } else if !((*mac).hmac_ctx).is_null() {
        ssh_hmac_free((*mac).hmac_ctx);
    }
    (*mac).hmac_ctx = 0 as *mut ssh_hmac_ctx;
    (*mac).umac_ctx = 0 as *mut umac_ctx;
}
pub unsafe extern "C" fn mac_valid(mut names: *const libc::c_char) -> libc::c_int {
    let mut maclist: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    if names.is_null()
        || strcmp(names, b"\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    cp = strdup(names);
    maclist = cp;
    if maclist.is_null() {
        return 0 as libc::c_int;
    }
    p = strsep(&mut cp, b",\0" as *const u8 as *const libc::c_char);
    while !p.is_null() && *p as libc::c_int != '\0' as i32 {
        if mac_setup(0 as *mut sshmac, p) < 0 as libc::c_int {
            libc::free(maclist as *mut libc::c_void);
            return 0 as libc::c_int;
        }
        p = strsep(&mut cp, b",\0" as *const u8 as *const libc::c_char);
    }
    libc::free(maclist as *mut libc::c_void);
    return 1 as libc::c_int;
}
