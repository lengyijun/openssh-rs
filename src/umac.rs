use ::libc;
extern "C" {
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);

    fn get_u32(_: *const libc::c_void) -> u_int32_t;
    fn put_u32(_: *mut libc::c_void, _: u_int32_t);
    fn get_u32_le(_: *const libc::c_void) -> u_int32_t;
    fn AES_set_encrypt_key(
        userKey: *const libc::c_uchar,
        bits: libc::c_int,
        key: *mut AES_KEY,
    ) -> libc::c_int;
    fn AES_encrypt(in_0: *const libc::c_uchar, out: *mut libc::c_uchar, key: *const AES_KEY);
}
pub type __u_char = libc::c_uchar;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type u_char = __u_char;
pub type size_t = libc::c_ulong;
pub type u_int8_t = __uint8_t;
pub type u_int16_t = __uint16_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type ptrdiff_t = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct umac_ctx {
    pub hash: uhash_ctx,
    pub pdf: pdf_ctx,
    pub free_ptr: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pdf_ctx {
    pub cache: [UINT8; 16],
    pub nonce: [UINT8; 16],
    pub prf_key: aes_int_key,
}
pub type aes_int_key = [AES_KEY; 1];
pub type AES_KEY = aes_key_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct aes_key_st {
    pub rd_key: [libc::c_uint; 60],
    pub rounds: libc::c_int,
}
pub type UINT8 = u_int8_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct uhash_ctx {
    pub hash: nh_ctx,
    pub poly_key_8: [UINT64; 2],
    pub poly_accum: [UINT64; 2],
    pub ip_keys: [UINT64; 8],
    pub ip_trans: [UINT32; 2],
    pub msg_len: UINT32,
}
pub type UINT32 = u_int32_t;
pub type UINT64 = u_int64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct nh_ctx {
    pub nh_key: [UINT8; 1040],
    pub data: [UINT8; 64],
    pub next_data_empty: libc::c_int,
    pub bytes_hashed: libc::c_int,
    pub state: [UINT64; 2],
}
pub type uhash_ctx_t = *mut uhash_ctx;
pub type UWORD = libc::c_uint;
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub tmp_nonce_lo: [UINT8; 4],
    pub align: UINT32,
}
pub type UINT16 = u_int16_t;
unsafe extern "C" fn kdf(
    mut bufp: *mut libc::c_void,
    mut key: *mut AES_KEY,
    mut ndx: UINT8,
    mut nbytes: libc::c_int,
) {
    let mut in_buf: [UINT8; 16] = [
        0 as libc::c_int as UINT8,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    let mut out_buf: [UINT8; 16] = [0; 16];
    let mut dst_buf: *mut UINT8 = bufp as *mut UINT8;
    let mut i: libc::c_int = 0;
    in_buf[(16 as libc::c_int - 9 as libc::c_int) as usize] = ndx;
    i = 1 as libc::c_int;
    in_buf[(16 as libc::c_int - 1 as libc::c_int) as usize] = i as UINT8;
    while nbytes >= 16 as libc::c_int {
        AES_encrypt(
            in_buf.as_mut_ptr() as *mut u_char,
            out_buf.as_mut_ptr() as *mut u_char,
            key,
        );
        memcpy(
            dst_buf as *mut libc::c_void,
            out_buf.as_mut_ptr() as *const libc::c_void,
            16 as libc::c_int as libc::c_ulong,
        );
        i += 1;
        in_buf[(16 as libc::c_int - 1 as libc::c_int) as usize] = i as UINT8;
        nbytes -= 16 as libc::c_int;
        dst_buf = dst_buf.offset(16 as libc::c_int as isize);
    }
    if nbytes != 0 {
        AES_encrypt(
            in_buf.as_mut_ptr() as *mut u_char,
            out_buf.as_mut_ptr() as *mut u_char,
            key,
        );
        memcpy(
            dst_buf as *mut libc::c_void,
            out_buf.as_mut_ptr() as *const libc::c_void,
            nbytes as libc::c_ulong,
        );
    }
    explicit_bzero(
        in_buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[UINT8; 16]>() as libc::c_ulong,
    );
    explicit_bzero(
        out_buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[UINT8; 16]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn pdf_init(mut pc: *mut pdf_ctx, mut prf_key: *mut AES_KEY) {
    let mut buf: [UINT8; 16] = [0; 16];
    kdf(
        buf.as_mut_ptr() as *mut libc::c_void,
        prf_key,
        0 as libc::c_int as UINT8,
        16 as libc::c_int,
    );
    AES_set_encrypt_key(
        buf.as_mut_ptr() as *const u_char,
        16 as libc::c_int * 8 as libc::c_int,
        ((*pc).prf_key).as_mut_ptr(),
    );
    memset(
        ((*pc).nonce).as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[UINT8; 16]>() as libc::c_ulong,
    );
    AES_encrypt(
        ((*pc).nonce).as_mut_ptr() as *mut u_char,
        ((*pc).cache).as_mut_ptr() as *mut u_char,
        ((*pc).prf_key).as_mut_ptr(),
    );
    explicit_bzero(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[UINT8; 16]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn pdf_gen_xor(
    mut pc: *mut pdf_ctx,
    mut nonce: *const UINT8,
    mut buf: *mut UINT8,
) {
    let mut t: C2RustUnnamed = C2RustUnnamed {
        tmp_nonce_lo: [0; 4],
    };
    let mut ndx: libc::c_int =
        *nonce.offset(7 as libc::c_int as isize) as libc::c_int & 1 as libc::c_int;
    *((t.tmp_nonce_lo).as_mut_ptr() as *mut UINT32) =
        *(nonce as *const UINT32).offset(1 as libc::c_int as isize);
    t.tmp_nonce_lo[3 as libc::c_int as usize] =
        (t.tmp_nonce_lo[3 as libc::c_int as usize] as libc::c_int & !(1 as libc::c_int)) as UINT8;
    if *((t.tmp_nonce_lo).as_mut_ptr() as *mut UINT32).offset(0 as libc::c_int as isize)
        != *(((*pc).nonce).as_mut_ptr() as *mut UINT32).offset(1 as libc::c_int as isize)
        || *(nonce as *const UINT32).offset(0 as libc::c_int as isize)
            != *(((*pc).nonce).as_mut_ptr() as *mut UINT32).offset(0 as libc::c_int as isize)
    {
        *(((*pc).nonce).as_mut_ptr() as *mut UINT32).offset(0 as libc::c_int as isize) =
            *(nonce as *const UINT32).offset(0 as libc::c_int as isize);
        *(((*pc).nonce).as_mut_ptr() as *mut UINT32).offset(1 as libc::c_int as isize) =
            *((t.tmp_nonce_lo).as_mut_ptr() as *mut UINT32).offset(0 as libc::c_int as isize);
        AES_encrypt(
            ((*pc).nonce).as_mut_ptr() as *mut u_char,
            ((*pc).cache).as_mut_ptr() as *mut u_char,
            ((*pc).prf_key).as_mut_ptr(),
        );
    }
    let ref mut fresh0 = *(buf as *mut UINT64);
    *fresh0 ^= *(((*pc).cache).as_mut_ptr() as *mut UINT64).offset(ndx as isize);
}
unsafe extern "C" fn nh_aux(
    mut kp: *mut libc::c_void,
    mut dp: *const libc::c_void,
    mut hp: *mut libc::c_void,
    mut dlen: UINT32,
) {
    let mut h1: UINT64 = 0;
    let mut h2: UINT64 = 0;
    let mut c: UWORD = dlen.wrapping_div(32 as libc::c_int as libc::c_uint);
    let mut k: *mut UINT32 = kp as *mut UINT32;
    let mut d: *const UINT32 = dp as *const UINT32;
    let mut d0: UINT32 = 0;
    let mut d1: UINT32 = 0;
    let mut d2: UINT32 = 0;
    let mut d3: UINT32 = 0;
    let mut d4: UINT32 = 0;
    let mut d5: UINT32 = 0;
    let mut d6: UINT32 = 0;
    let mut d7: UINT32 = 0;
    let mut k0: UINT32 = 0;
    let mut k1: UINT32 = 0;
    let mut k2: UINT32 = 0;
    let mut k3: UINT32 = 0;
    let mut k4: UINT32 = 0;
    let mut k5: UINT32 = 0;
    let mut k6: UINT32 = 0;
    let mut k7: UINT32 = 0;
    let mut k8: UINT32 = 0;
    let mut k9: UINT32 = 0;
    let mut k10: UINT32 = 0;
    let mut k11: UINT32 = 0;
    h1 = *(hp as *mut UINT64);
    h2 = *(hp as *mut UINT64).offset(1 as libc::c_int as isize);
    k0 = *k.offset(0 as libc::c_int as isize);
    k1 = *k.offset(1 as libc::c_int as isize);
    k2 = *k.offset(2 as libc::c_int as isize);
    k3 = *k.offset(3 as libc::c_int as isize);
    loop {
        d0 = get_u32_le(d.offset(0 as libc::c_int as isize) as *const libc::c_void);
        d1 = get_u32_le(d.offset(1 as libc::c_int as isize) as *const libc::c_void);
        d2 = get_u32_le(d.offset(2 as libc::c_int as isize) as *const libc::c_void);
        d3 = get_u32_le(d.offset(3 as libc::c_int as isize) as *const libc::c_void);
        d4 = get_u32_le(d.offset(4 as libc::c_int as isize) as *const libc::c_void);
        d5 = get_u32_le(d.offset(5 as libc::c_int as isize) as *const libc::c_void);
        d6 = get_u32_le(d.offset(6 as libc::c_int as isize) as *const libc::c_void);
        d7 = get_u32_le(d.offset(7 as libc::c_int as isize) as *const libc::c_void);
        k4 = *k.offset(4 as libc::c_int as isize);
        k5 = *k.offset(5 as libc::c_int as isize);
        k6 = *k.offset(6 as libc::c_int as isize);
        k7 = *k.offset(7 as libc::c_int as isize);
        k8 = *k.offset(8 as libc::c_int as isize);
        k9 = *k.offset(9 as libc::c_int as isize);
        k10 = *k.offset(10 as libc::c_int as isize);
        k11 = *k.offset(11 as libc::c_int as isize);
        h1 = (h1 as libc::c_ulong).wrapping_add(
            (k0.wrapping_add(d0) as UINT64).wrapping_mul(k4.wrapping_add(d4) as UINT64),
        ) as UINT64 as UINT64;
        h2 = (h2 as libc::c_ulong).wrapping_add(
            (k4.wrapping_add(d0) as UINT64).wrapping_mul(k8.wrapping_add(d4) as UINT64),
        ) as UINT64 as UINT64;
        h1 = (h1 as libc::c_ulong).wrapping_add(
            (k1.wrapping_add(d1) as UINT64).wrapping_mul(k5.wrapping_add(d5) as UINT64),
        ) as UINT64 as UINT64;
        h2 = (h2 as libc::c_ulong).wrapping_add(
            (k5.wrapping_add(d1) as UINT64).wrapping_mul(k9.wrapping_add(d5) as UINT64),
        ) as UINT64 as UINT64;
        h1 = (h1 as libc::c_ulong).wrapping_add(
            (k2.wrapping_add(d2) as UINT64).wrapping_mul(k6.wrapping_add(d6) as UINT64),
        ) as UINT64 as UINT64;
        h2 = (h2 as libc::c_ulong).wrapping_add(
            (k6.wrapping_add(d2) as UINT64).wrapping_mul(k10.wrapping_add(d6) as UINT64),
        ) as UINT64 as UINT64;
        h1 = (h1 as libc::c_ulong).wrapping_add(
            (k3.wrapping_add(d3) as UINT64).wrapping_mul(k7.wrapping_add(d7) as UINT64),
        ) as UINT64 as UINT64;
        h2 = (h2 as libc::c_ulong).wrapping_add(
            (k7.wrapping_add(d3) as UINT64).wrapping_mul(k11.wrapping_add(d7) as UINT64),
        ) as UINT64 as UINT64;
        k0 = k8;
        k1 = k9;
        k2 = k10;
        k3 = k11;
        d = d.offset(8 as libc::c_int as isize);
        k = k.offset(8 as libc::c_int as isize);
        c = c.wrapping_sub(1);
        if !(c != 0) {
            break;
        }
    }
    *(hp as *mut UINT64).offset(0 as libc::c_int as isize) = h1;
    *(hp as *mut UINT64).offset(1 as libc::c_int as isize) = h2;
}
unsafe extern "C" fn nh_transform(mut hc: *mut nh_ctx, mut buf: *const UINT8, mut nbytes: UINT32) {
    let mut key: *mut UINT8 = 0 as *mut UINT8;
    key = ((*hc).nh_key)
        .as_mut_ptr()
        .offset((*hc).bytes_hashed as isize);
    nh_aux(
        key as *mut libc::c_void,
        buf as *const libc::c_void,
        ((*hc).state).as_mut_ptr() as *mut libc::c_void,
        nbytes,
    );
}
unsafe extern "C" fn endian_convert(
    mut buf: *mut libc::c_void,
    mut bpw: UWORD,
    mut num_bytes: UINT32,
) {
    let mut iters: UWORD = num_bytes.wrapping_div(bpw);
    if bpw == 4 as libc::c_int as libc::c_uint {
        let mut p: *mut UINT32 = buf as *mut UINT32;
        loop {
            *p = get_u32(p as *const libc::c_void);
            p = p.offset(1);
            p;
            iters = iters.wrapping_sub(1);
            if !(iters != 0) {
                break;
            }
        }
    } else if bpw == 8 as libc::c_int as libc::c_uint {
        let mut p_0: *mut UINT32 = buf as *mut UINT32;
        let mut t: UINT32 = 0;
        loop {
            t = get_u32(p_0.offset(1 as libc::c_int as isize) as *const libc::c_void);
            *p_0.offset(1 as libc::c_int as isize) = get_u32(p_0 as *const libc::c_void);
            *p_0.offset(0 as libc::c_int as isize) = t;
            p_0 = p_0.offset(2 as libc::c_int as isize);
            iters = iters.wrapping_sub(1);
            if !(iters != 0) {
                break;
            }
        }
    }
}
unsafe extern "C" fn nh_reset(mut hc: *mut nh_ctx) {
    (*hc).bytes_hashed = 0 as libc::c_int;
    (*hc).next_data_empty = 0 as libc::c_int;
    (*hc).state[0 as libc::c_int as usize] = 0 as libc::c_int as UINT64;
    (*hc).state[1 as libc::c_int as usize] = 0 as libc::c_int as UINT64;
}
unsafe extern "C" fn nh_init(mut hc: *mut nh_ctx, mut prf_key: *mut AES_KEY) {
    kdf(
        ((*hc).nh_key).as_mut_ptr() as *mut libc::c_void,
        prf_key,
        1 as libc::c_int as UINT8,
        ::core::mem::size_of::<[UINT8; 1040]>() as libc::c_ulong as libc::c_int,
    );
    endian_convert(
        ((*hc).nh_key).as_mut_ptr() as *mut libc::c_void,
        4 as libc::c_int as UWORD,
        ::core::mem::size_of::<[UINT8; 1040]>() as libc::c_ulong as UINT32,
    );
    nh_reset(hc);
}
unsafe extern "C" fn nh_update(mut hc: *mut nh_ctx, mut buf: *const UINT8, mut nbytes: UINT32) {
    let mut i: UINT32 = 0;
    let mut j: UINT32 = 0;
    j = (*hc).next_data_empty as UINT32;
    if j.wrapping_add(nbytes) >= 64 as libc::c_int as libc::c_uint {
        if j != 0 {
            i = (64 as libc::c_int as libc::c_uint).wrapping_sub(j);
            memcpy(
                ((*hc).data).as_mut_ptr().offset(j as isize) as *mut libc::c_void,
                buf as *const libc::c_void,
                i as libc::c_ulong,
            );
            nh_transform(hc, ((*hc).data).as_mut_ptr(), 64 as libc::c_int as UINT32);
            nbytes = (nbytes as libc::c_uint).wrapping_sub(i) as UINT32 as UINT32;
            buf = buf.offset(i as isize);
            (*hc).bytes_hashed += 64 as libc::c_int;
        }
        if nbytes >= 64 as libc::c_int as libc::c_uint {
            i = nbytes & !(64 as libc::c_int - 1 as libc::c_int) as libc::c_uint;
            nh_transform(hc, buf, i);
            nbytes = (nbytes as libc::c_uint).wrapping_sub(i) as UINT32 as UINT32;
            buf = buf.offset(i as isize);
            (*hc).bytes_hashed =
                ((*hc).bytes_hashed as libc::c_uint).wrapping_add(i) as libc::c_int as libc::c_int;
        }
        j = 0 as libc::c_int as UINT32;
    }
    memcpy(
        ((*hc).data).as_mut_ptr().offset(j as isize) as *mut libc::c_void,
        buf as *const libc::c_void,
        nbytes as libc::c_ulong,
    );
    (*hc).next_data_empty = j.wrapping_add(nbytes) as libc::c_int;
}
unsafe extern "C" fn zero_pad(mut p: *mut UINT8, mut nbytes: libc::c_int) {
    if nbytes >= ::core::mem::size_of::<UWORD>() as libc::c_ulong as libc::c_int {
        while (p as ptrdiff_t as libc::c_ulong)
            .wrapping_rem(::core::mem::size_of::<UWORD>() as libc::c_ulong)
            != 0
        {
            *p = 0 as libc::c_int as UINT8;
            nbytes -= 1;
            nbytes;
            p = p.offset(1);
            p;
        }
        while nbytes >= ::core::mem::size_of::<UWORD>() as libc::c_ulong as libc::c_int {
            *(p as *mut UWORD) = 0 as libc::c_int as UWORD;
            nbytes = (nbytes as libc::c_ulong)
                .wrapping_sub(::core::mem::size_of::<UWORD>() as libc::c_ulong)
                as libc::c_int as libc::c_int;
            p = p.offset(::core::mem::size_of::<UWORD>() as libc::c_ulong as isize);
        }
    }
    while nbytes != 0 {
        *p = 0 as libc::c_int as UINT8;
        nbytes -= 1;
        nbytes;
        p = p.offset(1);
        p;
    }
}
unsafe extern "C" fn nh_final(mut hc: *mut nh_ctx, mut result: *mut UINT8) {
    let mut nh_len: libc::c_int = 0;
    let mut nbits: libc::c_int = 0;
    if (*hc).next_data_empty != 0 as libc::c_int {
        nh_len = (*hc).next_data_empty + (32 as libc::c_int - 1 as libc::c_int)
            & !(32 as libc::c_int - 1 as libc::c_int);
        zero_pad(
            ((*hc).data)
                .as_mut_ptr()
                .offset((*hc).next_data_empty as isize),
            nh_len - (*hc).next_data_empty,
        );
        nh_transform(hc, ((*hc).data).as_mut_ptr(), nh_len as UINT32);
        (*hc).bytes_hashed += (*hc).next_data_empty;
    } else if (*hc).bytes_hashed == 0 as libc::c_int {
        nh_len = 32 as libc::c_int;
        zero_pad(((*hc).data).as_mut_ptr(), 32 as libc::c_int);
        nh_transform(hc, ((*hc).data).as_mut_ptr(), nh_len as UINT32);
    }
    nbits = (*hc).bytes_hashed << 3 as libc::c_int;
    *(result as *mut UINT64).offset(0 as libc::c_int as isize) =
        (*((*hc).state).as_mut_ptr().offset(0 as libc::c_int as isize))
            .wrapping_add(nbits as libc::c_ulong);
    *(result as *mut UINT64).offset(1 as libc::c_int as isize) =
        (*((*hc).state).as_mut_ptr().offset(1 as libc::c_int as isize))
            .wrapping_add(nbits as libc::c_ulong);
    nh_reset(hc);
}
unsafe extern "C" fn nh(
    mut hc: *mut nh_ctx,
    mut buf: *const UINT8,
    mut padded_len: UINT32,
    mut unpadded_len: UINT32,
    mut result: *mut UINT8,
) {
    let mut nbits: UINT32 = 0;
    nbits = unpadded_len << 3 as libc::c_int;
    *(result as *mut UINT64).offset(0 as libc::c_int as isize) = nbits as UINT64;
    *(result as *mut UINT64).offset(1 as libc::c_int as isize) = nbits as UINT64;
    nh_aux(
        ((*hc).nh_key).as_mut_ptr() as *mut libc::c_void,
        buf as *const libc::c_void,
        result as *mut libc::c_void,
        padded_len,
    );
}
unsafe extern "C" fn poly64(mut cur: UINT64, mut key: UINT64, mut data: UINT64) -> UINT64 {
    let mut key_hi: UINT32 = (key >> 32 as libc::c_int) as UINT32;
    let mut key_lo: UINT32 = key as UINT32;
    let mut cur_hi: UINT32 = (cur >> 32 as libc::c_int) as UINT32;
    let mut cur_lo: UINT32 = cur as UINT32;
    let mut x_lo: UINT32 = 0;
    let mut x_hi: UINT32 = 0;
    let mut X: UINT64 = 0;
    let mut T: UINT64 = 0;
    let mut res: UINT64 = 0;
    X = (key_hi as UINT64)
        .wrapping_mul(cur_lo as UINT64)
        .wrapping_add((cur_hi as UINT64).wrapping_mul(key_lo as UINT64));
    x_lo = X as UINT32;
    x_hi = (X >> 32 as libc::c_int) as UINT32;
    res = (key_hi as UINT64)
        .wrapping_mul(cur_hi as UINT64)
        .wrapping_add(x_hi as libc::c_ulong)
        .wrapping_mul(59 as libc::c_int as libc::c_ulong)
        .wrapping_add((key_lo as UINT64).wrapping_mul(cur_lo as UINT64));
    T = (x_lo as UINT64) << 32 as libc::c_int;
    res = (res as libc::c_ulong).wrapping_add(T) as UINT64 as UINT64;
    if res < T {
        res = (res as libc::c_ulong).wrapping_add(59 as libc::c_int as libc::c_ulong) as UINT64
            as UINT64;
    }
    res = (res as libc::c_ulong).wrapping_add(data) as UINT64 as UINT64;
    if res < data {
        res = (res as libc::c_ulong).wrapping_add(59 as libc::c_int as libc::c_ulong) as UINT64
            as UINT64;
    }
    return res;
}
unsafe extern "C" fn poly_hash(mut hc: uhash_ctx_t, mut data_in: *mut UINT32) {
    let mut i: libc::c_int = 0;
    let mut data: *mut UINT64 = data_in as *mut UINT64;
    i = 0 as libc::c_int;
    while i < 8 as libc::c_int / 4 as libc::c_int {
        if (*data.offset(i as isize) >> 32 as libc::c_int) as UINT32 as libc::c_ulong
            == 0xffffffff as libc::c_ulong
        {
            (*hc).poly_accum[i as usize] = poly64(
                (*hc).poly_accum[i as usize],
                (*hc).poly_key_8[i as usize],
                (0xffffffffffffffc5 as libc::c_ulonglong as UINT64)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            );
            (*hc).poly_accum[i as usize] = poly64(
                (*hc).poly_accum[i as usize],
                (*hc).poly_key_8[i as usize],
                (*data.offset(i as isize)).wrapping_sub(59 as libc::c_int as libc::c_ulong),
            );
        } else {
            (*hc).poly_accum[i as usize] = poly64(
                (*hc).poly_accum[i as usize],
                (*hc).poly_key_8[i as usize],
                *data.offset(i as isize),
            );
        }
        i += 1;
        i;
    }
}
unsafe extern "C" fn ip_aux(mut t: UINT64, mut ipkp: *mut UINT64, mut data: UINT64) -> UINT64 {
    t = t.wrapping_add(
        (*ipkp.offset(0 as libc::c_int as isize))
            .wrapping_mul((data >> 48 as libc::c_int) as UINT16 as UINT64),
    );
    t = t.wrapping_add(
        (*ipkp.offset(1 as libc::c_int as isize))
            .wrapping_mul((data >> 32 as libc::c_int) as UINT16 as UINT64),
    );
    t = t.wrapping_add(
        (*ipkp.offset(2 as libc::c_int as isize))
            .wrapping_mul((data >> 16 as libc::c_int) as UINT16 as UINT64),
    );
    t = t.wrapping_add(
        (*ipkp.offset(3 as libc::c_int as isize)).wrapping_mul(data as UINT16 as UINT64),
    );
    return t;
}
unsafe extern "C" fn ip_reduce_p36(mut t: UINT64) -> UINT32 {
    let mut ret: UINT64 = 0;
    ret = (t & 0xfffffffff as libc::c_ulonglong as UINT64)
        .wrapping_add((5 as libc::c_int as libc::c_ulong).wrapping_mul(t >> 36 as libc::c_int));
    if ret >= 0xffffffffb as libc::c_ulonglong as UINT64 {
        ret = (ret as libc::c_ulong).wrapping_sub(0xffffffffb as libc::c_ulonglong as UINT64)
            as UINT64 as UINT64;
    }
    return ret as UINT32;
}
unsafe extern "C" fn ip_short(mut ahc: uhash_ctx_t, mut nh_res: *mut UINT8, mut res: *mut u_char) {
    let mut t: UINT64 = 0;
    let mut nhp: *mut UINT64 = nh_res as *mut UINT64;
    t = ip_aux(
        0 as libc::c_int as UINT64,
        ((*ahc).ip_keys).as_mut_ptr(),
        *nhp.offset(0 as libc::c_int as isize),
    );
    put_u32(
        (res as *mut UINT32).offset(0 as libc::c_int as isize) as *mut libc::c_void,
        ip_reduce_p36(t) ^ (*ahc).ip_trans[0 as libc::c_int as usize],
    );
    t = ip_aux(
        0 as libc::c_int as UINT64,
        ((*ahc).ip_keys)
            .as_mut_ptr()
            .offset(4 as libc::c_int as isize),
        *nhp.offset(1 as libc::c_int as isize),
    );
    put_u32(
        (res as *mut UINT32).offset(1 as libc::c_int as isize) as *mut libc::c_void,
        ip_reduce_p36(t) ^ (*ahc).ip_trans[1 as libc::c_int as usize],
    );
}
unsafe extern "C" fn ip_long(mut ahc: uhash_ctx_t, mut res: *mut u_char) {
    let mut i: libc::c_int = 0;
    let mut t: UINT64 = 0;
    i = 0 as libc::c_int;
    while i < 8 as libc::c_int / 4 as libc::c_int {
        if (*ahc).poly_accum[i as usize] >= 0xffffffffffffffc5 as libc::c_ulonglong as UINT64 {
            (*ahc).poly_accum[i as usize] = ((*ahc).poly_accum[i as usize] as libc::c_ulong)
                .wrapping_sub(0xffffffffffffffc5 as libc::c_ulonglong as UINT64)
                as UINT64 as UINT64;
        }
        t = ip_aux(
            0 as libc::c_int as UINT64,
            ((*ahc).ip_keys)
                .as_mut_ptr()
                .offset((i * 4 as libc::c_int) as isize),
            (*ahc).poly_accum[i as usize],
        );
        put_u32(
            (res as *mut UINT32).offset(i as isize) as *mut libc::c_void,
            ip_reduce_p36(t) ^ (*ahc).ip_trans[i as usize],
        );
        i += 1;
        i;
    }
}
unsafe extern "C" fn uhash_reset(mut pc: uhash_ctx_t) -> libc::c_int {
    nh_reset(&mut (*pc).hash);
    (*pc).msg_len = 0 as libc::c_int as UINT32;
    (*pc).poly_accum[0 as libc::c_int as usize] = 1 as libc::c_int as UINT64;
    (*pc).poly_accum[1 as libc::c_int as usize] = 1 as libc::c_int as UINT64;
    return 1 as libc::c_int;
}
unsafe extern "C" fn uhash_init(mut ahc: uhash_ctx_t, mut prf_key: *mut AES_KEY) {
    let mut i: libc::c_int = 0;
    let mut buf: [UINT8; 160] = [0; 160];
    memset(
        ahc as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<uhash_ctx>() as libc::c_ulong,
    );
    nh_init(&mut (*ahc).hash, prf_key);
    kdf(
        buf.as_mut_ptr() as *mut libc::c_void,
        prf_key,
        2 as libc::c_int as UINT8,
        ::core::mem::size_of::<[UINT8; 160]>() as libc::c_ulong as libc::c_int,
    );
    i = 0 as libc::c_int;
    while i < 8 as libc::c_int / 4 as libc::c_int {
        memcpy(
            ((*ahc).poly_key_8).as_mut_ptr().offset(i as isize) as *mut libc::c_void,
            buf.as_mut_ptr().offset((24 as libc::c_int * i) as isize) as *const libc::c_void,
            8 as libc::c_int as libc::c_ulong,
        );
        endian_convert(
            ((*ahc).poly_key_8).as_mut_ptr().offset(i as isize) as *mut libc::c_void,
            8 as libc::c_int as UWORD,
            8 as libc::c_int as UINT32,
        );
        (*ahc).poly_key_8[i as usize] &= ((0x1ffffff as libc::c_uint as UINT64)
            << 32 as libc::c_int)
            .wrapping_add(0x1ffffff as libc::c_uint as libc::c_ulong);
        (*ahc).poly_accum[i as usize] = 1 as libc::c_int as UINT64;
        i += 1;
        i;
    }
    kdf(
        buf.as_mut_ptr() as *mut libc::c_void,
        prf_key,
        3 as libc::c_int as UINT8,
        ::core::mem::size_of::<[UINT8; 160]>() as libc::c_ulong as libc::c_int,
    );
    i = 0 as libc::c_int;
    while i < 8 as libc::c_int / 4 as libc::c_int {
        memcpy(
            ((*ahc).ip_keys)
                .as_mut_ptr()
                .offset((4 as libc::c_int * i) as isize) as *mut libc::c_void,
            buf.as_mut_ptr().offset(
                ((8 as libc::c_int * i + 4 as libc::c_int) as libc::c_ulong)
                    .wrapping_mul(::core::mem::size_of::<UINT64>() as libc::c_ulong)
                    as isize,
            ) as *const libc::c_void,
            (4 as libc::c_int as libc::c_ulong)
                .wrapping_mul(::core::mem::size_of::<UINT64>() as libc::c_ulong),
        );
        i += 1;
        i;
    }
    endian_convert(
        ((*ahc).ip_keys).as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<UINT64>() as libc::c_ulong as UWORD,
        ::core::mem::size_of::<[UINT64; 8]>() as libc::c_ulong as UINT32,
    );
    i = 0 as libc::c_int;
    while i < 8 as libc::c_int / 4 as libc::c_int * 4 as libc::c_int {
        (*ahc).ip_keys[i as usize] = ((*ahc).ip_keys[i as usize] as libc::c_ulong)
            .wrapping_rem(0xffffffffb as libc::c_ulonglong as UINT64)
            as UINT64 as UINT64;
        i += 1;
        i;
    }
    kdf(
        ((*ahc).ip_trans).as_mut_ptr() as *mut libc::c_void,
        prf_key,
        4 as libc::c_int as UINT8,
        ((8 as libc::c_int / 4 as libc::c_int) as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<UINT32>() as libc::c_ulong) as libc::c_int,
    );
    endian_convert(
        ((*ahc).ip_trans).as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<UINT32>() as libc::c_ulong as UWORD,
        ((8 as libc::c_int / 4 as libc::c_int) as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<UINT32>() as libc::c_ulong) as UINT32,
    );
    explicit_bzero(
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[UINT8; 160]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn uhash_update(
    mut ctx: uhash_ctx_t,
    mut input: *const u_char,
    mut len: libc::c_long,
) -> libc::c_int {
    let mut bytes_hashed: UWORD = 0;
    let mut bytes_remaining: UWORD = 0;
    let mut result_buf: [UINT64; 2] = [0; 2];
    let mut nh_result: *mut UINT8 = &mut result_buf as *mut [UINT64; 2] as *mut UINT8;
    if (*ctx).msg_len as libc::c_long + len <= 1024 as libc::c_int as libc::c_long {
        nh_update(&mut (*ctx).hash, input as *const UINT8, len as UINT32);
        (*ctx).msg_len = ((*ctx).msg_len as libc::c_long + len) as UINT32;
    } else {
        bytes_hashed = ((*ctx).msg_len).wrapping_rem(1024 as libc::c_int as libc::c_uint);
        if (*ctx).msg_len == 1024 as libc::c_int as libc::c_uint {
            bytes_hashed = 1024 as libc::c_int as UWORD;
        }
        if bytes_hashed as libc::c_long + len >= 1024 as libc::c_int as libc::c_long {
            if bytes_hashed != 0 {
                bytes_remaining = (1024 as libc::c_int as libc::c_uint).wrapping_sub(bytes_hashed);
                nh_update(&mut (*ctx).hash, input as *const UINT8, bytes_remaining);
                nh_final(&mut (*ctx).hash, nh_result);
                (*ctx).msg_len = ((*ctx).msg_len as libc::c_uint).wrapping_add(bytes_remaining)
                    as UINT32 as UINT32;
                poly_hash(ctx, nh_result as *mut UINT32);
                len -= bytes_remaining as libc::c_long;
                input = input.offset(bytes_remaining as isize);
            }
            while len >= 1024 as libc::c_int as libc::c_long {
                nh(
                    &mut (*ctx).hash,
                    input as *const UINT8,
                    1024 as libc::c_int as UINT32,
                    1024 as libc::c_int as UINT32,
                    nh_result,
                );
                (*ctx).msg_len = ((*ctx).msg_len as libc::c_uint)
                    .wrapping_add(1024 as libc::c_int as libc::c_uint)
                    as UINT32 as UINT32;
                len -= 1024 as libc::c_int as libc::c_long;
                input = input.offset(1024 as libc::c_int as isize);
                poly_hash(ctx, nh_result as *mut UINT32);
            }
        }
        if len != 0 {
            nh_update(&mut (*ctx).hash, input as *const UINT8, len as UINT32);
            (*ctx).msg_len = ((*ctx).msg_len as libc::c_long + len) as UINT32;
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn uhash_final(mut ctx: uhash_ctx_t, mut res: *mut u_char) -> libc::c_int {
    let mut result_buf: [UINT64; 2] = [0; 2];
    let mut nh_result: *mut UINT8 = &mut result_buf as *mut [UINT64; 2] as *mut UINT8;
    if (*ctx).msg_len > 1024 as libc::c_int as libc::c_uint {
        if ((*ctx).msg_len).wrapping_rem(1024 as libc::c_int as libc::c_uint) != 0 {
            nh_final(&mut (*ctx).hash, nh_result);
            poly_hash(ctx, nh_result as *mut UINT32);
        }
        ip_long(ctx, res);
    } else {
        nh_final(&mut (*ctx).hash, nh_result);
        ip_short(ctx, nh_result, res);
    }
    uhash_reset(ctx);
    return 1 as libc::c_int;
}
pub static mut umac_ctx: umac_ctx = umac_ctx {
    hash: uhash_ctx {
        hash: nh_ctx {
            nh_key: [0; 1040],
            data: [0; 64],
            next_data_empty: 0,
            bytes_hashed: 0,
            state: [0; 2],
        },
        poly_key_8: [0; 2],
        poly_accum: [0; 2],
        ip_keys: [0; 8],
        ip_trans: [0; 2],
        msg_len: 0,
    },
    pdf: pdf_ctx {
        cache: [0; 16],
        nonce: [0; 16],
        prf_key: [AES_KEY {
            rd_key: [0; 60],
            rounds: 0,
        }; 1],
    },
    free_ptr: 0 as *const libc::c_void as *mut libc::c_void,
};
pub unsafe extern "C" fn umac_delete(mut ctx: *mut umac_ctx) -> libc::c_int {
    if !ctx.is_null() {
        ctx = (*ctx).free_ptr as *mut umac_ctx;
        freezero(
            ctx as *mut libc::c_void,
            (::core::mem::size_of::<umac_ctx>() as libc::c_ulong)
                .wrapping_add(16 as libc::c_int as libc::c_ulong),
        );
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn umac_new(mut key: *const u_char) -> *mut umac_ctx {
    let mut ctx: *mut umac_ctx = 0 as *mut umac_ctx;
    let mut octx: *mut umac_ctx = 0 as *mut umac_ctx;
    let mut bytes_to_add: size_t = 0;
    let mut prf_key: aes_int_key = [AES_KEY {
        rd_key: [0; 60],
        rounds: 0,
    }; 1];
    ctx = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        (::core::mem::size_of::<umac_ctx>() as libc::c_ulong)
            .wrapping_add(16 as libc::c_int as libc::c_ulong),
    ) as *mut umac_ctx;
    octx = ctx;
    if !ctx.is_null() {
        bytes_to_add = (16 as libc::c_int as libc::c_long
            - (ctx as ptrdiff_t & (16 as libc::c_int - 1 as libc::c_int) as libc::c_long))
            as size_t;
        ctx = (ctx as *mut u_char).offset(bytes_to_add as isize) as *mut umac_ctx;
        (*ctx).free_ptr = octx as *mut libc::c_void;
        AES_set_encrypt_key(
            key,
            16 as libc::c_int * 8 as libc::c_int,
            prf_key.as_mut_ptr(),
        );
        pdf_init(&mut (*ctx).pdf, prf_key.as_mut_ptr());
        uhash_init(&mut (*ctx).hash, prf_key.as_mut_ptr());
        explicit_bzero(
            prf_key.as_mut_ptr() as *mut libc::c_void,
            ::core::mem::size_of::<aes_int_key>() as libc::c_ulong,
        );
    }
    return ctx;
}
pub unsafe extern "C" fn umac_final(
    mut ctx: *mut umac_ctx,
    mut tag: *mut u_char,
    mut nonce: *const u_char,
) -> libc::c_int {
    uhash_final(&mut (*ctx).hash, tag);
    pdf_gen_xor(&mut (*ctx).pdf, nonce as *const UINT8, tag as *mut UINT8);
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn umac_update(
    mut ctx: *mut umac_ctx,
    mut input: *const u_char,
    mut len: libc::c_long,
) -> libc::c_int {
    uhash_update(&mut (*ctx).hash, input, len);
    return 1 as libc::c_int;
}
