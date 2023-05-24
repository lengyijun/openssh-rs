use ::libc;
extern "C" {
    fn arc4random_buf(_: *mut libc::c_void, _: size_t);
    fn crypto_hash_sha512(
        _: *mut libc::c_uchar,
        _: *const libc::c_uchar,
        _: libc::c_ulonglong,
    ) -> libc::c_int;
}
pub type __int8_t = libc::c_schar;
pub type __int16_t = libc::c_short;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type size_t = libc::c_ulong;
pub type int8_t = __int8_t;
pub type int16_t = __int16_t;
pub type int32_t = __int32_t;
pub type int64_t = __int64_t;
pub type uint32_t = __uint32_t;
pub type uint16_t = __uint16_t;
pub type uint64_t = __uint64_t;
pub type crypto_int8 = int8_t;
pub type crypto_int16 = int16_t;
pub type crypto_uint16 = uint16_t;
pub type crypto_int32 = int32_t;
pub type crypto_uint32 = uint32_t;
pub type crypto_uint64 = uint64_t;
pub type small = crypto_int8;
pub type Inputs = [small; 761];
pub type Fq = crypto_int16;
unsafe extern "C" fn crypto_sort_int32(mut array: *mut libc::c_void, mut n: libc::c_longlong) {
    let mut top: libc::c_longlong = 0;
    let mut p_0: libc::c_longlong = 0;
    let mut q_0: libc::c_longlong = 0;
    let mut r: libc::c_longlong = 0;
    let mut i: libc::c_longlong = 0;
    let mut j: libc::c_longlong = 0;
    let mut x: *mut crypto_int32 = array as *mut crypto_int32;
    if n < 2 as libc::c_int as libc::c_longlong {
        return;
    }
    top = 1 as libc::c_int as libc::c_longlong;
    while top < n - top {
        top += top;
    }
    p_0 = top;
    while p_0 >= 1 as libc::c_int as libc::c_longlong {
        i = 0 as libc::c_int as libc::c_longlong;
        while i + 2 as libc::c_int as libc::c_longlong * p_0 <= n {
            j = i;
            while j < i + p_0 {
                let mut ab: int64_t =
                    *x.offset((j + p_0) as isize) as int64_t ^ *x.offset(j as isize) as int64_t;
                let mut c: int64_t =
                    *x.offset((j + p_0) as isize) as int64_t - *x.offset(j as isize) as int64_t;
                c ^= ab & (c ^ *x.offset((j + p_0) as isize) as libc::c_long);
                c >>= 31 as libc::c_int;
                c &= ab;
                let ref mut fresh0 = *x.offset(j as isize);
                *fresh0 = (*fresh0 as libc::c_long ^ c) as crypto_int32;
                let ref mut fresh1 = *x.offset((j + p_0) as isize);
                *fresh1 = (*fresh1 as libc::c_long ^ c) as crypto_int32;
                j += 1;
                j;
            }
            i += 2 as libc::c_int as libc::c_longlong * p_0;
        }
        j = i;
        while j < n - p_0 {
            let mut ab_0: int64_t =
                *x.offset((j + p_0) as isize) as int64_t ^ *x.offset(j as isize) as int64_t;
            let mut c_0: int64_t =
                *x.offset((j + p_0) as isize) as int64_t - *x.offset(j as isize) as int64_t;
            c_0 ^= ab_0 & (c_0 ^ *x.offset((j + p_0) as isize) as libc::c_long);
            c_0 >>= 31 as libc::c_int;
            c_0 &= ab_0;
            let ref mut fresh2 = *x.offset(j as isize);
            *fresh2 = (*fresh2 as libc::c_long ^ c_0) as crypto_int32;
            let ref mut fresh3 = *x.offset((j + p_0) as isize);
            *fresh3 = (*fresh3 as libc::c_long ^ c_0) as crypto_int32;
            j += 1;
            j;
        }
        i = 0 as libc::c_int as libc::c_longlong;
        j = 0 as libc::c_int as libc::c_longlong;
        q_0 = top;
        while q_0 > p_0 {
            let mut current_block_73: u64;
            if j != i {
                loop {
                    if j == n - q_0 {
                        current_block_73 = 7419121793134201633;
                        break;
                    }
                    let mut a: crypto_int32 = *x.offset((j + p_0) as isize);
                    r = q_0;
                    while r > p_0 {
                        let mut ab_1: int64_t =
                            *x.offset((j + r) as isize) as int64_t ^ a as int64_t;
                        let mut c_1: int64_t =
                            *x.offset((j + r) as isize) as int64_t - a as int64_t;
                        c_1 ^= ab_1 & (c_1 ^ *x.offset((j + r) as isize) as libc::c_long);
                        c_1 >>= 31 as libc::c_int;
                        c_1 &= ab_1;
                        a = (a as libc::c_long ^ c_1) as crypto_int32;
                        let ref mut fresh4 = *x.offset((j + r) as isize);
                        *fresh4 = (*fresh4 as libc::c_long ^ c_1) as crypto_int32;
                        r >>= 1 as libc::c_int;
                    }
                    *x.offset((j + p_0) as isize) = a;
                    j += 1;
                    j;
                    if !(j == i + p_0) {
                        continue;
                    }
                    i += 2 as libc::c_int as libc::c_longlong * p_0;
                    current_block_73 = 721385680381463314;
                    break;
                }
            } else {
                current_block_73 = 721385680381463314;
            }
            match current_block_73 {
                721385680381463314 => {
                    while i + p_0 <= n - q_0 {
                        j = i;
                        while j < i + p_0 {
                            let mut a_0: crypto_int32 = *x.offset((j + p_0) as isize);
                            r = q_0;
                            while r > p_0 {
                                let mut ab_2: int64_t =
                                    *x.offset((j + r) as isize) as int64_t ^ a_0 as int64_t;
                                let mut c_2: int64_t =
                                    *x.offset((j + r) as isize) as int64_t - a_0 as int64_t;
                                c_2 ^= ab_2 & (c_2 ^ *x.offset((j + r) as isize) as libc::c_long);
                                c_2 >>= 31 as libc::c_int;
                                c_2 &= ab_2;
                                a_0 = (a_0 as libc::c_long ^ c_2) as crypto_int32;
                                let ref mut fresh5 = *x.offset((j + r) as isize);
                                *fresh5 = (*fresh5 as libc::c_long ^ c_2) as crypto_int32;
                                r >>= 1 as libc::c_int;
                            }
                            *x.offset((j + p_0) as isize) = a_0;
                            j += 1;
                            j;
                        }
                        i += 2 as libc::c_int as libc::c_longlong * p_0;
                    }
                    j = i;
                    while j < n - q_0 {
                        let mut a_1: crypto_int32 = *x.offset((j + p_0) as isize);
                        r = q_0;
                        while r > p_0 {
                            let mut ab_3: int64_t =
                                *x.offset((j + r) as isize) as int64_t ^ a_1 as int64_t;
                            let mut c_3: int64_t =
                                *x.offset((j + r) as isize) as int64_t - a_1 as int64_t;
                            c_3 ^= ab_3 & (c_3 ^ *x.offset((j + r) as isize) as libc::c_long);
                            c_3 >>= 31 as libc::c_int;
                            c_3 &= ab_3;
                            a_1 = (a_1 as libc::c_long ^ c_3) as crypto_int32;
                            let ref mut fresh6 = *x.offset((j + r) as isize);
                            *fresh6 = (*fresh6 as libc::c_long ^ c_3) as crypto_int32;
                            r >>= 1 as libc::c_int;
                        }
                        *x.offset((j + p_0) as isize) = a_1;
                        j += 1;
                        j;
                    }
                }
                _ => {}
            }
            q_0 >>= 1 as libc::c_int;
        }
        p_0 >>= 1 as libc::c_int;
    }
}
unsafe extern "C" fn crypto_sort_uint32(mut array: *mut libc::c_void, mut n: libc::c_longlong) {
    let mut x: *mut crypto_uint32 = array as *mut crypto_uint32;
    let mut j: libc::c_longlong = 0;
    j = 0 as libc::c_int as libc::c_longlong;
    while j < n {
        let ref mut fresh7 = *x.offset(j as isize);
        *fresh7 ^= 0x80000000 as libc::c_uint;
        j += 1;
        j;
    }
    crypto_sort_int32(array, n);
    j = 0 as libc::c_int as libc::c_longlong;
    while j < n {
        let ref mut fresh8 = *x.offset(j as isize);
        *fresh8 ^= 0x80000000 as libc::c_uint;
        j += 1;
        j;
    }
}
unsafe extern "C" fn uint32_divmod_uint14(
    mut q_0: *mut crypto_uint32,
    mut r: *mut crypto_uint16,
    mut x: crypto_uint32,
    mut m: crypto_uint16,
) {
    let mut v: crypto_uint32 = 0x80000000 as libc::c_uint;
    let mut qpart: crypto_uint32 = 0;
    let mut mask: crypto_uint32 = 0;
    v = (v as libc::c_uint).wrapping_div(m as libc::c_uint) as crypto_uint32 as crypto_uint32;
    *q_0 = 0 as libc::c_int as crypto_uint32;
    qpart = ((x as libc::c_ulong).wrapping_mul(v as crypto_uint64) >> 31 as libc::c_int)
        as crypto_uint32;
    x = (x as libc::c_uint).wrapping_sub(qpart.wrapping_mul(m as libc::c_uint)) as crypto_uint32
        as crypto_uint32;
    *q_0 = (*q_0 as libc::c_uint).wrapping_add(qpart) as crypto_uint32 as crypto_uint32;
    qpart = ((x as libc::c_ulong).wrapping_mul(v as crypto_uint64) >> 31 as libc::c_int)
        as crypto_uint32;
    x = (x as libc::c_uint).wrapping_sub(qpart.wrapping_mul(m as libc::c_uint)) as crypto_uint32
        as crypto_uint32;
    *q_0 = (*q_0 as libc::c_uint).wrapping_add(qpart) as crypto_uint32 as crypto_uint32;
    x = (x as libc::c_uint).wrapping_sub(m as libc::c_uint) as crypto_uint32 as crypto_uint32;
    *q_0 = (*q_0 as libc::c_uint).wrapping_add(1 as libc::c_int as libc::c_uint) as crypto_uint32
        as crypto_uint32;
    mask = (x >> 31 as libc::c_int).wrapping_neg();
    x = (x as libc::c_uint).wrapping_add(mask & m as crypto_uint32) as crypto_uint32
        as crypto_uint32;
    *q_0 = (*q_0 as libc::c_uint).wrapping_add(mask) as crypto_uint32 as crypto_uint32;
    *r = x as crypto_uint16;
}
unsafe extern "C" fn uint32_mod_uint14(
    mut x: crypto_uint32,
    mut m: crypto_uint16,
) -> crypto_uint16 {
    let mut q_0: crypto_uint32 = 0;
    let mut r: crypto_uint16 = 0;
    uint32_divmod_uint14(&mut q_0, &mut r, x, m);
    return r;
}
unsafe extern "C" fn int32_divmod_uint14(
    mut q_0: *mut crypto_int32,
    mut r: *mut crypto_uint16,
    mut x: crypto_int32,
    mut m: crypto_uint16,
) {
    let mut uq: crypto_uint32 = 0;
    let mut uq2: crypto_uint32 = 0;
    let mut ur: crypto_uint16 = 0;
    let mut ur2: crypto_uint16 = 0;
    let mut mask: crypto_uint32 = 0;
    uint32_divmod_uint14(
        &mut uq,
        &mut ur,
        (0x80000000 as libc::c_uint).wrapping_add(x as crypto_uint32),
        m,
    );
    uint32_divmod_uint14(&mut uq2, &mut ur2, 0x80000000 as libc::c_uint, m);
    ur = (ur as libc::c_int - ur2 as libc::c_int) as crypto_uint16;
    uq = (uq as libc::c_uint).wrapping_sub(uq2) as crypto_uint32 as crypto_uint32;
    mask = ((ur as libc::c_int >> 15 as libc::c_int) as crypto_uint32).wrapping_neg();
    ur = (ur as libc::c_uint).wrapping_add(mask & m as libc::c_uint) as crypto_uint16
        as crypto_uint16;
    uq = (uq as libc::c_uint).wrapping_add(mask) as crypto_uint32 as crypto_uint32;
    *r = ur;
    *q_0 = uq as crypto_int32;
}
unsafe extern "C" fn int32_mod_uint14(mut x: crypto_int32, mut m: crypto_uint16) -> crypto_uint16 {
    let mut q_0: crypto_int32 = 0;
    let mut r: crypto_uint16 = 0;
    int32_divmod_uint14(&mut q_0, &mut r, x, m);
    return r;
}
unsafe extern "C" fn Decode(
    mut out: *mut crypto_uint16,
    mut S: *const libc::c_uchar,
    mut M: *const crypto_uint16,
    mut len: libc::c_longlong,
) {
    if len == 1 as libc::c_int as libc::c_longlong {
        if *M.offset(0 as libc::c_int as isize) as libc::c_int == 1 as libc::c_int {
            *out = 0 as libc::c_int as crypto_uint16;
        } else if *M.offset(0 as libc::c_int as isize) as libc::c_int <= 256 as libc::c_int {
            *out = uint32_mod_uint14(
                *S.offset(0 as libc::c_int as isize) as crypto_uint32,
                *M.offset(0 as libc::c_int as isize),
            );
        } else {
            *out = uint32_mod_uint14(
                (*S.offset(0 as libc::c_int as isize) as libc::c_int
                    + ((*S.offset(1 as libc::c_int as isize) as crypto_uint16 as libc::c_int)
                        << 8 as libc::c_int)) as crypto_uint32,
                *M.offset(0 as libc::c_int as isize),
            );
        }
    }
    if len > 1 as libc::c_int as libc::c_longlong {
        let vla = ((len + 1 as libc::c_int as libc::c_longlong)
            / 2 as libc::c_int as libc::c_longlong) as usize;
        let mut R2: Vec<crypto_uint16> = ::std::vec::from_elem(0, vla);
        let vla_0 = ((len + 1 as libc::c_int as libc::c_longlong)
            / 2 as libc::c_int as libc::c_longlong) as usize;
        let mut M2: Vec<crypto_uint16> = ::std::vec::from_elem(0, vla_0);
        let vla_1 = (len / 2 as libc::c_int as libc::c_longlong) as usize;
        let mut bottomr: Vec<crypto_uint16> = ::std::vec::from_elem(0, vla_1);
        let vla_2 = (len / 2 as libc::c_int as libc::c_longlong) as usize;
        let mut bottomt: Vec<crypto_uint32> = ::std::vec::from_elem(0, vla_2);
        let mut i: libc::c_longlong = 0;
        i = 0 as libc::c_int as libc::c_longlong;
        while i < len - 1 as libc::c_int as libc::c_longlong {
            let mut m: crypto_uint32 = (*M.offset(i as isize) as libc::c_uint).wrapping_mul(
                *M.offset((i + 1 as libc::c_int as libc::c_longlong) as isize) as crypto_uint32,
            );
            if m > (256 as libc::c_int * 16383 as libc::c_int) as libc::c_uint {
                *bottomt
                    .as_mut_ptr()
                    .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) =
                    (256 as libc::c_int * 256 as libc::c_int) as crypto_uint32;
                *bottomr
                    .as_mut_ptr()
                    .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) =
                    (*S.offset(0 as libc::c_int as isize) as libc::c_int
                        + 256 as libc::c_int * *S.offset(1 as libc::c_int as isize) as libc::c_int)
                        as crypto_uint16;
                S = S.offset(2 as libc::c_int as isize);
                *M2.as_mut_ptr()
                    .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) =
                    ((m.wrapping_add(255 as libc::c_int as libc::c_uint) >> 8 as libc::c_int)
                        .wrapping_add(255 as libc::c_int as libc::c_uint)
                        >> 8 as libc::c_int) as crypto_uint16;
            } else if m >= 16384 as libc::c_int as libc::c_uint {
                *bottomt
                    .as_mut_ptr()
                    .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) =
                    256 as libc::c_int as crypto_uint32;
                *bottomr
                    .as_mut_ptr()
                    .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) =
                    *S.offset(0 as libc::c_int as isize) as crypto_uint16;
                S = S.offset(1 as libc::c_int as isize);
                *M2.as_mut_ptr()
                    .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) =
                    (m.wrapping_add(255 as libc::c_int as libc::c_uint) >> 8 as libc::c_int)
                        as crypto_uint16;
            } else {
                *bottomt
                    .as_mut_ptr()
                    .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) =
                    1 as libc::c_int as crypto_uint32;
                *bottomr
                    .as_mut_ptr()
                    .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) =
                    0 as libc::c_int as crypto_uint16;
                *M2.as_mut_ptr()
                    .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) =
                    m as crypto_uint16;
            }
            i += 2 as libc::c_int as libc::c_longlong;
        }
        if i < len {
            *M2.as_mut_ptr()
                .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) =
                *M.offset(i as isize);
        }
        Decode(
            R2.as_mut_ptr(),
            S,
            M2.as_mut_ptr(),
            (len + 1 as libc::c_int as libc::c_longlong) / 2 as libc::c_int as libc::c_longlong,
        );
        i = 0 as libc::c_int as libc::c_longlong;
        while i < len - 1 as libc::c_int as libc::c_longlong {
            let mut r: crypto_uint32 = *bottomr
                .as_mut_ptr()
                .offset((i / 2 as libc::c_int as libc::c_longlong) as isize)
                as crypto_uint32;
            let mut r1: crypto_uint32 = 0;
            let mut r0: crypto_uint16 = 0;
            r = (r as libc::c_uint).wrapping_add(
                (*bottomt
                    .as_mut_ptr()
                    .offset((i / 2 as libc::c_int as libc::c_longlong) as isize))
                .wrapping_mul(
                    *R2.as_mut_ptr()
                        .offset((i / 2 as libc::c_int as libc::c_longlong) as isize)
                        as libc::c_uint,
                ),
            ) as crypto_uint32 as crypto_uint32;
            uint32_divmod_uint14(&mut r1, &mut r0, r, *M.offset(i as isize));
            r1 = uint32_mod_uint14(
                r1,
                *M.offset((i + 1 as libc::c_int as libc::c_longlong) as isize),
            ) as crypto_uint32;
            let fresh9 = out;
            out = out.offset(1);
            *fresh9 = r0;
            let fresh10 = out;
            out = out.offset(1);
            *fresh10 = r1 as crypto_uint16;
            i += 2 as libc::c_int as libc::c_longlong;
        }
        if i < len {
            let fresh11 = out;
            out = out.offset(1);
            *fresh11 = *R2
                .as_mut_ptr()
                .offset((i / 2 as libc::c_int as libc::c_longlong) as isize);
        }
    }
}
unsafe extern "C" fn Encode(
    mut out: *mut libc::c_uchar,
    mut R: *const crypto_uint16,
    mut M: *const crypto_uint16,
    mut len: libc::c_longlong,
) {
    if len == 1 as libc::c_int as libc::c_longlong {
        let mut r: crypto_uint16 = *R.offset(0 as libc::c_int as isize);
        let mut m: crypto_uint16 = *M.offset(0 as libc::c_int as isize);
        while m as libc::c_int > 1 as libc::c_int {
            let fresh12 = out;
            out = out.offset(1);
            *fresh12 = r as libc::c_uchar;
            r = (r as libc::c_int >> 8 as libc::c_int) as crypto_uint16;
            m = (m as libc::c_int + 255 as libc::c_int >> 8 as libc::c_int) as crypto_uint16;
        }
    }
    if len > 1 as libc::c_int as libc::c_longlong {
        let vla = ((len + 1 as libc::c_int as libc::c_longlong)
            / 2 as libc::c_int as libc::c_longlong) as usize;
        let mut R2: Vec<crypto_uint16> = ::std::vec::from_elem(0, vla);
        let vla_0 = ((len + 1 as libc::c_int as libc::c_longlong)
            / 2 as libc::c_int as libc::c_longlong) as usize;
        let mut M2: Vec<crypto_uint16> = ::std::vec::from_elem(0, vla_0);
        let mut i: libc::c_longlong = 0;
        i = 0 as libc::c_int as libc::c_longlong;
        while i < len - 1 as libc::c_int as libc::c_longlong {
            let mut m0: crypto_uint32 = *M.offset(i as isize) as crypto_uint32;
            let mut r_0: crypto_uint32 = (*R.offset(i as isize) as libc::c_uint).wrapping_add(
                (*R.offset((i + 1 as libc::c_int as libc::c_longlong) as isize) as libc::c_uint)
                    .wrapping_mul(m0),
            );
            let mut m_0: crypto_uint32 =
                (*M.offset((i + 1 as libc::c_int as libc::c_longlong) as isize) as libc::c_uint)
                    .wrapping_mul(m0);
            while m_0 >= 16384 as libc::c_int as libc::c_uint {
                let fresh13 = out;
                out = out.offset(1);
                *fresh13 = r_0 as libc::c_uchar;
                r_0 >>= 8 as libc::c_int;
                m_0 = m_0.wrapping_add(255 as libc::c_int as libc::c_uint) >> 8 as libc::c_int;
            }
            *R2.as_mut_ptr()
                .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) = r_0 as crypto_uint16;
            *M2.as_mut_ptr()
                .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) = m_0 as crypto_uint16;
            i += 2 as libc::c_int as libc::c_longlong;
        }
        if i < len {
            *R2.as_mut_ptr()
                .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) =
                *R.offset(i as isize);
            *M2.as_mut_ptr()
                .offset((i / 2 as libc::c_int as libc::c_longlong) as isize) =
                *M.offset(i as isize);
        }
        Encode(
            out,
            R2.as_mut_ptr(),
            M2.as_mut_ptr(),
            (len + 1 as libc::c_int as libc::c_longlong) / 2 as libc::c_int as libc::c_longlong,
        );
    }
}
unsafe extern "C" fn int16_nonzero_mask(mut x: crypto_int16) -> libc::c_int {
    let mut u: crypto_uint16 = x as crypto_uint16;
    let mut v: crypto_uint32 = u as crypto_uint32;
    v = v.wrapping_neg();
    v >>= 31 as libc::c_int;
    return v.wrapping_neg() as libc::c_int;
}
unsafe extern "C" fn int16_negative_mask(mut x: crypto_int16) -> libc::c_int {
    let mut u: crypto_uint16 = x as crypto_uint16;
    u = (u as libc::c_int >> 15 as libc::c_int) as crypto_uint16;
    return -(u as libc::c_int);
}
unsafe extern "C" fn F3_freeze(mut x: crypto_int16) -> small {
    return (int32_mod_uint14(
        x as libc::c_int + 1 as libc::c_int,
        3 as libc::c_int as crypto_uint16,
    ) as libc::c_int
        - 1 as libc::c_int) as small;
}
unsafe extern "C" fn Fq_freeze(mut x: crypto_int32) -> Fq {
    return (int32_mod_uint14(
        x + (4591 as libc::c_int - 1 as libc::c_int) / 2 as libc::c_int,
        4591 as libc::c_int as crypto_uint16,
    ) as libc::c_int
        - (4591 as libc::c_int - 1 as libc::c_int) / 2 as libc::c_int) as Fq;
}
unsafe extern "C" fn Fq_recip(mut a1: Fq) -> Fq {
    let mut i: libc::c_int = 1 as libc::c_int;
    let mut ai: Fq = a1;
    while i < 4591 as libc::c_int - 2 as libc::c_int {
        ai = Fq_freeze(a1 as libc::c_int * ai as crypto_int32);
        i += 1 as libc::c_int;
    }
    return ai;
}
unsafe extern "C" fn Weightw_mask(mut r: *mut small) -> libc::c_int {
    let mut weight: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        weight += *r.offset(i as isize) as libc::c_int & 1 as libc::c_int;
        i += 1;
        i;
    }
    return int16_nonzero_mask((weight - 286 as libc::c_int) as crypto_int16);
}
unsafe extern "C" fn R3_fromRq(mut out: *mut small, mut r: *const Fq) {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        *out.offset(i as isize) = F3_freeze(*r.offset(i as isize));
        i += 1;
        i;
    }
}
unsafe extern "C" fn R3_mult(mut h: *mut small, mut f: *const small, mut g: *const small) {
    let mut fg: [small; 1521] = [0; 1521];
    let mut result: small = 0;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        result = 0 as libc::c_int as small;
        j = 0 as libc::c_int;
        while j <= i {
            result = F3_freeze(
                (result as libc::c_int
                    + *f.offset(j as isize) as libc::c_int
                        * *g.offset((i - j) as isize) as libc::c_int)
                    as crypto_int16,
            );
            j += 1;
            j;
        }
        fg[i as usize] = result;
        i += 1;
        i;
    }
    i = 761 as libc::c_int;
    while i < 761 as libc::c_int + 761 as libc::c_int - 1 as libc::c_int {
        result = 0 as libc::c_int as small;
        j = i - 761 as libc::c_int + 1 as libc::c_int;
        while j < 761 as libc::c_int {
            result = F3_freeze(
                (result as libc::c_int
                    + *f.offset(j as isize) as libc::c_int
                        * *g.offset((i - j) as isize) as libc::c_int)
                    as crypto_int16,
            );
            j += 1;
            j;
        }
        fg[i as usize] = result;
        i += 1;
        i;
    }
    i = 761 as libc::c_int + 761 as libc::c_int - 2 as libc::c_int;
    while i >= 761 as libc::c_int {
        fg[(i - 761 as libc::c_int) as usize] = F3_freeze(
            (fg[(i - 761 as libc::c_int) as usize] as libc::c_int + fg[i as usize] as libc::c_int)
                as crypto_int16,
        );
        fg[(i - 761 as libc::c_int + 1 as libc::c_int) as usize] = F3_freeze(
            (fg[(i - 761 as libc::c_int + 1 as libc::c_int) as usize] as libc::c_int
                + fg[i as usize] as libc::c_int) as crypto_int16,
        );
        i -= 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        *h.offset(i as isize) = fg[i as usize];
        i += 1;
        i;
    }
}
unsafe extern "C" fn R3_recip(mut out: *mut small, mut in_0: *const small) -> libc::c_int {
    let mut f: [small; 762] = [0; 762];
    let mut g: [small; 762] = [0; 762];
    let mut v: [small; 762] = [0; 762];
    let mut r: [small; 762] = [0; 762];
    let mut i: libc::c_int = 0;
    let mut loop_0: libc::c_int = 0;
    let mut delta: libc::c_int = 0;
    let mut sign: libc::c_int = 0;
    let mut swap: libc::c_int = 0;
    let mut t: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int + 1 as libc::c_int {
        v[i as usize] = 0 as libc::c_int as small;
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int + 1 as libc::c_int {
        r[i as usize] = 0 as libc::c_int as small;
        i += 1;
        i;
    }
    r[0 as libc::c_int as usize] = 1 as libc::c_int as small;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        f[i as usize] = 0 as libc::c_int as small;
        i += 1;
        i;
    }
    f[0 as libc::c_int as usize] = 1 as libc::c_int as small;
    f[761 as libc::c_int as usize] = -(1 as libc::c_int) as small;
    f[(761 as libc::c_int - 1 as libc::c_int) as usize] = f[761 as libc::c_int as usize];
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        g[(761 as libc::c_int - 1 as libc::c_int - i) as usize] = *in_0.offset(i as isize);
        i += 1;
        i;
    }
    g[761 as libc::c_int as usize] = 0 as libc::c_int as small;
    delta = 1 as libc::c_int;
    loop_0 = 0 as libc::c_int;
    while loop_0 < 2 as libc::c_int * 761 as libc::c_int - 1 as libc::c_int {
        i = 761 as libc::c_int;
        while i > 0 as libc::c_int {
            v[i as usize] = v[(i - 1 as libc::c_int) as usize];
            i -= 1;
            i;
        }
        v[0 as libc::c_int as usize] = 0 as libc::c_int as small;
        sign = -(g[0 as libc::c_int as usize] as libc::c_int)
            * f[0 as libc::c_int as usize] as libc::c_int;
        swap = int16_negative_mask(-delta as crypto_int16)
            & int16_nonzero_mask(g[0 as libc::c_int as usize] as crypto_int16);
        delta ^= swap & (delta ^ -delta);
        delta += 1 as libc::c_int;
        i = 0 as libc::c_int;
        while i < 761 as libc::c_int + 1 as libc::c_int {
            t = swap & (f[i as usize] as libc::c_int ^ g[i as usize] as libc::c_int);
            f[i as usize] = (f[i as usize] as libc::c_int ^ t) as small;
            g[i as usize] = (g[i as usize] as libc::c_int ^ t) as small;
            t = swap & (v[i as usize] as libc::c_int ^ r[i as usize] as libc::c_int);
            v[i as usize] = (v[i as usize] as libc::c_int ^ t) as small;
            r[i as usize] = (r[i as usize] as libc::c_int ^ t) as small;
            i += 1;
            i;
        }
        i = 0 as libc::c_int;
        while i < 761 as libc::c_int + 1 as libc::c_int {
            g[i as usize] = F3_freeze(
                (g[i as usize] as libc::c_int + sign * f[i as usize] as libc::c_int)
                    as crypto_int16,
            );
            i += 1;
            i;
        }
        i = 0 as libc::c_int;
        while i < 761 as libc::c_int + 1 as libc::c_int {
            r[i as usize] = F3_freeze(
                (r[i as usize] as libc::c_int + sign * v[i as usize] as libc::c_int)
                    as crypto_int16,
            );
            i += 1;
            i;
        }
        i = 0 as libc::c_int;
        while i < 761 as libc::c_int {
            g[i as usize] = g[(i + 1 as libc::c_int) as usize];
            i += 1;
            i;
        }
        g[761 as libc::c_int as usize] = 0 as libc::c_int as small;
        loop_0 += 1;
        loop_0;
    }
    sign = f[0 as libc::c_int as usize] as libc::c_int;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        *out.offset(i as isize) = (sign
            * v[(761 as libc::c_int - 1 as libc::c_int - i) as usize] as libc::c_int)
            as small;
        i += 1;
        i;
    }
    return int16_nonzero_mask(delta as crypto_int16);
}
unsafe extern "C" fn Rq_mult_small(mut h: *mut Fq, mut f: *const Fq, mut g: *const small) {
    let mut fg: [Fq; 1521] = [0; 1521];
    let mut result: Fq = 0;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        result = 0 as libc::c_int as Fq;
        j = 0 as libc::c_int;
        while j <= i {
            result = Fq_freeze(
                result as libc::c_int
                    + *f.offset(j as isize) as libc::c_int
                        * *g.offset((i - j) as isize) as crypto_int32,
            );
            j += 1;
            j;
        }
        fg[i as usize] = result;
        i += 1;
        i;
    }
    i = 761 as libc::c_int;
    while i < 761 as libc::c_int + 761 as libc::c_int - 1 as libc::c_int {
        result = 0 as libc::c_int as Fq;
        j = i - 761 as libc::c_int + 1 as libc::c_int;
        while j < 761 as libc::c_int {
            result = Fq_freeze(
                result as libc::c_int
                    + *f.offset(j as isize) as libc::c_int
                        * *g.offset((i - j) as isize) as crypto_int32,
            );
            j += 1;
            j;
        }
        fg[i as usize] = result;
        i += 1;
        i;
    }
    i = 761 as libc::c_int + 761 as libc::c_int - 2 as libc::c_int;
    while i >= 761 as libc::c_int {
        fg[(i - 761 as libc::c_int) as usize] = Fq_freeze(
            fg[(i - 761 as libc::c_int) as usize] as libc::c_int + fg[i as usize] as libc::c_int,
        );
        fg[(i - 761 as libc::c_int + 1 as libc::c_int) as usize] = Fq_freeze(
            fg[(i - 761 as libc::c_int + 1 as libc::c_int) as usize] as libc::c_int
                + fg[i as usize] as libc::c_int,
        );
        i -= 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        *h.offset(i as isize) = fg[i as usize];
        i += 1;
        i;
    }
}
unsafe extern "C" fn Rq_mult3(mut h: *mut Fq, mut f: *const Fq) {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        *h.offset(i as isize) = Fq_freeze(3 as libc::c_int * *f.offset(i as isize) as libc::c_int);
        i += 1;
        i;
    }
}
unsafe extern "C" fn Rq_recip3(mut out: *mut Fq, mut in_0: *const small) -> libc::c_int {
    let mut f: [Fq; 762] = [0; 762];
    let mut g: [Fq; 762] = [0; 762];
    let mut v: [Fq; 762] = [0; 762];
    let mut r: [Fq; 762] = [0; 762];
    let mut i: libc::c_int = 0;
    let mut loop_0: libc::c_int = 0;
    let mut delta: libc::c_int = 0;
    let mut swap: libc::c_int = 0;
    let mut t: libc::c_int = 0;
    let mut f0: crypto_int32 = 0;
    let mut g0: crypto_int32 = 0;
    let mut scale: Fq = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int + 1 as libc::c_int {
        v[i as usize] = 0 as libc::c_int as Fq;
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int + 1 as libc::c_int {
        r[i as usize] = 0 as libc::c_int as Fq;
        i += 1;
        i;
    }
    r[0 as libc::c_int as usize] = Fq_recip(3 as libc::c_int as Fq);
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        f[i as usize] = 0 as libc::c_int as Fq;
        i += 1;
        i;
    }
    f[0 as libc::c_int as usize] = 1 as libc::c_int as Fq;
    f[761 as libc::c_int as usize] = -(1 as libc::c_int) as Fq;
    f[(761 as libc::c_int - 1 as libc::c_int) as usize] = f[761 as libc::c_int as usize];
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        g[(761 as libc::c_int - 1 as libc::c_int - i) as usize] = *in_0.offset(i as isize) as Fq;
        i += 1;
        i;
    }
    g[761 as libc::c_int as usize] = 0 as libc::c_int as Fq;
    delta = 1 as libc::c_int;
    loop_0 = 0 as libc::c_int;
    while loop_0 < 2 as libc::c_int * 761 as libc::c_int - 1 as libc::c_int {
        i = 761 as libc::c_int;
        while i > 0 as libc::c_int {
            v[i as usize] = v[(i - 1 as libc::c_int) as usize];
            i -= 1;
            i;
        }
        v[0 as libc::c_int as usize] = 0 as libc::c_int as Fq;
        swap = int16_negative_mask(-delta as crypto_int16)
            & int16_nonzero_mask(g[0 as libc::c_int as usize]);
        delta ^= swap & (delta ^ -delta);
        delta += 1 as libc::c_int;
        i = 0 as libc::c_int;
        while i < 761 as libc::c_int + 1 as libc::c_int {
            t = swap & (f[i as usize] as libc::c_int ^ g[i as usize] as libc::c_int);
            f[i as usize] = (f[i as usize] as libc::c_int ^ t) as Fq;
            g[i as usize] = (g[i as usize] as libc::c_int ^ t) as Fq;
            t = swap & (v[i as usize] as libc::c_int ^ r[i as usize] as libc::c_int);
            v[i as usize] = (v[i as usize] as libc::c_int ^ t) as Fq;
            r[i as usize] = (r[i as usize] as libc::c_int ^ t) as Fq;
            i += 1;
            i;
        }
        f0 = f[0 as libc::c_int as usize] as crypto_int32;
        g0 = g[0 as libc::c_int as usize] as crypto_int32;
        i = 0 as libc::c_int;
        while i < 761 as libc::c_int + 1 as libc::c_int {
            g[i as usize] =
                Fq_freeze(f0 * g[i as usize] as libc::c_int - g0 * f[i as usize] as libc::c_int);
            i += 1;
            i;
        }
        i = 0 as libc::c_int;
        while i < 761 as libc::c_int + 1 as libc::c_int {
            r[i as usize] =
                Fq_freeze(f0 * r[i as usize] as libc::c_int - g0 * v[i as usize] as libc::c_int);
            i += 1;
            i;
        }
        i = 0 as libc::c_int;
        while i < 761 as libc::c_int {
            g[i as usize] = g[(i + 1 as libc::c_int) as usize];
            i += 1;
            i;
        }
        g[761 as libc::c_int as usize] = 0 as libc::c_int as Fq;
        loop_0 += 1;
        loop_0;
    }
    scale = Fq_recip(f[0 as libc::c_int as usize]);
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        *out.offset(i as isize) = Fq_freeze(
            scale as libc::c_int
                * v[(761 as libc::c_int - 1 as libc::c_int - i) as usize] as crypto_int32,
        );
        i += 1;
        i;
    }
    return int16_nonzero_mask(delta as crypto_int16);
}
unsafe extern "C" fn Round(mut out: *mut Fq, mut a: *const Fq) {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        *out.offset(i as isize) = (*a.offset(i as isize) as libc::c_int
            - F3_freeze(*a.offset(i as isize)) as libc::c_int)
            as Fq;
        i += 1;
        i;
    }
}
unsafe extern "C" fn Short_fromlist(mut out: *mut small, mut in_0: *const crypto_uint32) {
    let mut L: [crypto_uint32; 761] = [0; 761];
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 286 as libc::c_int {
        L[i as usize] = *in_0.offset(i as isize) & -(2 as libc::c_int) as crypto_uint32;
        i += 1;
        i;
    }
    i = 286 as libc::c_int;
    while i < 761 as libc::c_int {
        L[i as usize] = *in_0.offset(i as isize) & -(3 as libc::c_int) as crypto_uint32
            | 1 as libc::c_int as libc::c_uint;
        i += 1;
        i;
    }
    crypto_sort_uint32(
        L.as_mut_ptr() as *mut libc::c_void,
        761 as libc::c_int as libc::c_longlong,
    );
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        *out.offset(i as isize) = (L[i as usize] & 3 as libc::c_int as libc::c_uint)
            .wrapping_sub(1 as libc::c_int as libc::c_uint)
            as small;
        i += 1;
        i;
    }
}
unsafe extern "C" fn Hash_prefix(
    mut out: *mut libc::c_uchar,
    mut b: libc::c_int,
    mut in_0: *const libc::c_uchar,
    mut inlen: libc::c_int,
) {
    let vla = (inlen + 1 as libc::c_int) as usize;
    let mut x: Vec<libc::c_uchar> = ::std::vec::from_elem(0, vla);
    let mut h: [libc::c_uchar; 64] = [0; 64];
    let mut i: libc::c_int = 0;
    *x.as_mut_ptr().offset(0 as libc::c_int as isize) = b as libc::c_uchar;
    i = 0 as libc::c_int;
    while i < inlen {
        *x.as_mut_ptr().offset((i + 1 as libc::c_int) as isize) = *in_0.offset(i as isize);
        i += 1;
        i;
    }
    crypto_hash_sha512(
        h.as_mut_ptr(),
        x.as_mut_ptr(),
        (inlen + 1 as libc::c_int) as libc::c_ulonglong,
    );
    i = 0 as libc::c_int;
    while i < 32 as libc::c_int {
        *out.offset(i as isize) = h[i as usize];
        i += 1;
        i;
    }
}
unsafe extern "C" fn urandom32() -> crypto_uint32 {
    let mut c: [libc::c_uchar; 4] = [0; 4];
    let mut out: [crypto_uint32; 4] = [0; 4];
    arc4random_buf(
        c.as_mut_ptr() as *mut libc::c_void,
        4 as libc::c_int as size_t,
    );
    out[0 as libc::c_int as usize] = c[0 as libc::c_int as usize] as crypto_uint32;
    out[1 as libc::c_int as usize] =
        (c[1 as libc::c_int as usize] as crypto_uint32) << 8 as libc::c_int;
    out[2 as libc::c_int as usize] =
        (c[2 as libc::c_int as usize] as crypto_uint32) << 16 as libc::c_int;
    out[3 as libc::c_int as usize] =
        (c[3 as libc::c_int as usize] as crypto_uint32) << 24 as libc::c_int;
    return (out[0 as libc::c_int as usize])
        .wrapping_add(out[1 as libc::c_int as usize])
        .wrapping_add(out[2 as libc::c_int as usize])
        .wrapping_add(out[3 as libc::c_int as usize]);
}
unsafe extern "C" fn Short_random(mut out: *mut small) {
    let mut L: [crypto_uint32; 761] = [0; 761];
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        L[i as usize] = urandom32();
        i += 1;
        i;
    }
    Short_fromlist(out, L.as_mut_ptr());
}
unsafe extern "C" fn Small_random(mut out: *mut small) {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        *out.offset(i as isize) = ((urandom32() & 0x3fffffff as libc::c_int as libc::c_uint)
            .wrapping_mul(3 as libc::c_int as libc::c_uint)
            >> 30 as libc::c_int)
            .wrapping_sub(1 as libc::c_int as libc::c_uint)
            as small;
        i += 1;
        i;
    }
}
unsafe extern "C" fn KeyGen(mut h: *mut Fq, mut f: *mut small, mut ginv: *mut small) {
    let mut g: [small; 761] = [0; 761];
    let mut finv: [Fq; 761] = [0; 761];
    loop {
        Small_random(g.as_mut_ptr());
        if R3_recip(ginv, g.as_mut_ptr()) == 0 as libc::c_int {
            break;
        }
    }
    Short_random(f);
    Rq_recip3(finv.as_mut_ptr(), f);
    Rq_mult_small(h, finv.as_mut_ptr(), g.as_mut_ptr());
}
unsafe extern "C" fn Encrypt(mut c: *mut Fq, mut r: *const small, mut h: *const Fq) {
    let mut hr: [Fq; 761] = [0; 761];
    Rq_mult_small(hr.as_mut_ptr(), h, r);
    Round(c, hr.as_mut_ptr());
}
unsafe extern "C" fn Decrypt(
    mut r: *mut small,
    mut c: *const Fq,
    mut f: *const small,
    mut ginv: *const small,
) {
    let mut cf: [Fq; 761] = [0; 761];
    let mut cf3: [Fq; 761] = [0; 761];
    let mut e: [small; 761] = [0; 761];
    let mut ev: [small; 761] = [0; 761];
    let mut mask: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    Rq_mult_small(cf.as_mut_ptr(), c, f);
    Rq_mult3(cf3.as_mut_ptr(), cf.as_mut_ptr());
    R3_fromRq(e.as_mut_ptr(), cf3.as_mut_ptr());
    R3_mult(ev.as_mut_ptr(), e.as_mut_ptr(), ginv);
    mask = Weightw_mask(ev.as_mut_ptr());
    i = 0 as libc::c_int;
    while i < 286 as libc::c_int {
        *r.offset(i as isize) = ((ev[i as usize] as libc::c_int ^ 1 as libc::c_int) & !mask
            ^ 1 as libc::c_int) as small;
        i += 1;
        i;
    }
    i = 286 as libc::c_int;
    while i < 761 as libc::c_int {
        *r.offset(i as isize) = (ev[i as usize] as libc::c_int & !mask) as small;
        i += 1;
        i;
    }
}
unsafe extern "C" fn Small_encode(mut s: *mut libc::c_uchar, mut f: *const small) {
    let mut x: small = 0;
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int / 4 as libc::c_int {
        let fresh14 = f;
        f = f.offset(1);
        x = (*fresh14 as libc::c_int + 1 as libc::c_int) as small;
        let fresh15 = f;
        f = f.offset(1);
        x = (x as libc::c_int + ((*fresh15 as libc::c_int + 1 as libc::c_int) << 2 as libc::c_int))
            as small;
        let fresh16 = f;
        f = f.offset(1);
        x = (x as libc::c_int + ((*fresh16 as libc::c_int + 1 as libc::c_int) << 4 as libc::c_int))
            as small;
        let fresh17 = f;
        f = f.offset(1);
        x = (x as libc::c_int + ((*fresh17 as libc::c_int + 1 as libc::c_int) << 6 as libc::c_int))
            as small;
        let fresh18 = s;
        s = s.offset(1);
        *fresh18 = x as libc::c_uchar;
        i += 1;
        i;
    }
    let fresh19 = f;
    f = f.offset(1);
    x = (*fresh19 as libc::c_int + 1 as libc::c_int) as small;
    let fresh20 = s;
    s = s.offset(1);
    *fresh20 = x as libc::c_uchar;
}
unsafe extern "C" fn Small_decode(mut f: *mut small, mut s: *const libc::c_uchar) {
    let mut x: libc::c_uchar = 0;
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int / 4 as libc::c_int {
        let fresh21 = s;
        s = s.offset(1);
        x = *fresh21;
        let fresh22 = f;
        f = f.offset(1);
        *fresh22 = ((x as libc::c_int & 3 as libc::c_int) as small as libc::c_int
            - 1 as libc::c_int) as small;
        x = (x as libc::c_int >> 2 as libc::c_int) as libc::c_uchar;
        let fresh23 = f;
        f = f.offset(1);
        *fresh23 = ((x as libc::c_int & 3 as libc::c_int) as small as libc::c_int
            - 1 as libc::c_int) as small;
        x = (x as libc::c_int >> 2 as libc::c_int) as libc::c_uchar;
        let fresh24 = f;
        f = f.offset(1);
        *fresh24 = ((x as libc::c_int & 3 as libc::c_int) as small as libc::c_int
            - 1 as libc::c_int) as small;
        x = (x as libc::c_int >> 2 as libc::c_int) as libc::c_uchar;
        let fresh25 = f;
        f = f.offset(1);
        *fresh25 = ((x as libc::c_int & 3 as libc::c_int) as small as libc::c_int
            - 1 as libc::c_int) as small;
        i += 1;
        i;
    }
    let fresh26 = s;
    s = s.offset(1);
    x = *fresh26;
    let fresh27 = f;
    f = f.offset(1);
    *fresh27 =
        ((x as libc::c_int & 3 as libc::c_int) as small as libc::c_int - 1 as libc::c_int) as small;
}
unsafe extern "C" fn Rq_encode(mut s: *mut libc::c_uchar, mut r: *const Fq) {
    let mut R: [crypto_uint16; 761] = [0; 761];
    let mut M: [crypto_uint16; 761] = [0; 761];
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        R[i as usize] = (*r.offset(i as isize) as libc::c_int
            + (4591 as libc::c_int - 1 as libc::c_int) / 2 as libc::c_int)
            as crypto_uint16;
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        M[i as usize] = 4591 as libc::c_int as crypto_uint16;
        i += 1;
        i;
    }
    Encode(
        s,
        R.as_mut_ptr(),
        M.as_mut_ptr(),
        761 as libc::c_int as libc::c_longlong,
    );
}
unsafe extern "C" fn Rq_decode(mut r: *mut Fq, mut s: *const libc::c_uchar) {
    let mut R: [crypto_uint16; 761] = [0; 761];
    let mut M: [crypto_uint16; 761] = [0; 761];
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        M[i as usize] = 4591 as libc::c_int as crypto_uint16;
        i += 1;
        i;
    }
    Decode(
        R.as_mut_ptr(),
        s,
        M.as_mut_ptr(),
        761 as libc::c_int as libc::c_longlong,
    );
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        *r.offset(i as isize) = (R[i as usize] as Fq as libc::c_int
            - (4591 as libc::c_int - 1 as libc::c_int) / 2 as libc::c_int)
            as Fq;
        i += 1;
        i;
    }
}
unsafe extern "C" fn Rounded_encode(mut s: *mut libc::c_uchar, mut r: *const Fq) {
    let mut R: [crypto_uint16; 761] = [0; 761];
    let mut M: [crypto_uint16; 761] = [0; 761];
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        R[i as usize] = ((*r.offset(i as isize) as libc::c_int
            + (4591 as libc::c_int - 1 as libc::c_int) / 2 as libc::c_int)
            * 10923 as libc::c_int
            >> 15 as libc::c_int) as crypto_uint16;
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        M[i as usize] =
            ((4591 as libc::c_int + 2 as libc::c_int) / 3 as libc::c_int) as crypto_uint16;
        i += 1;
        i;
    }
    Encode(
        s,
        R.as_mut_ptr(),
        M.as_mut_ptr(),
        761 as libc::c_int as libc::c_longlong,
    );
}
unsafe extern "C" fn Rounded_decode(mut r: *mut Fq, mut s: *const libc::c_uchar) {
    let mut R: [crypto_uint16; 761] = [0; 761];
    let mut M: [crypto_uint16; 761] = [0; 761];
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        M[i as usize] =
            ((4591 as libc::c_int + 2 as libc::c_int) / 3 as libc::c_int) as crypto_uint16;
        i += 1;
        i;
    }
    Decode(
        R.as_mut_ptr(),
        s,
        M.as_mut_ptr(),
        761 as libc::c_int as libc::c_longlong,
    );
    i = 0 as libc::c_int;
    while i < 761 as libc::c_int {
        *r.offset(i as isize) = (R[i as usize] as libc::c_int * 3 as libc::c_int
            - (4591 as libc::c_int - 1 as libc::c_int) / 2 as libc::c_int)
            as Fq;
        i += 1;
        i;
    }
}
unsafe extern "C" fn ZKeyGen(mut pk: *mut libc::c_uchar, mut sk: *mut libc::c_uchar) {
    let mut h: [Fq; 761] = [0; 761];
    let mut f: [small; 761] = [0; 761];
    let mut v: [small; 761] = [0; 761];
    KeyGen(h.as_mut_ptr(), f.as_mut_ptr(), v.as_mut_ptr());
    Rq_encode(pk, h.as_mut_ptr());
    Small_encode(sk, f.as_mut_ptr());
    sk = sk.offset(((761 as libc::c_int + 3 as libc::c_int) / 4 as libc::c_int) as isize);
    Small_encode(sk, v.as_mut_ptr());
}
unsafe extern "C" fn ZEncrypt(
    mut C: *mut libc::c_uchar,
    mut r: *const small,
    mut pk: *const libc::c_uchar,
) {
    let mut h: [Fq; 761] = [0; 761];
    let mut c: [Fq; 761] = [0; 761];
    Rq_decode(h.as_mut_ptr(), pk);
    Encrypt(c.as_mut_ptr(), r, h.as_mut_ptr());
    Rounded_encode(C, c.as_mut_ptr());
}
unsafe extern "C" fn ZDecrypt(
    mut r: *mut small,
    mut C: *const libc::c_uchar,
    mut sk: *const libc::c_uchar,
) {
    let mut f: [small; 761] = [0; 761];
    let mut v: [small; 761] = [0; 761];
    let mut c: [Fq; 761] = [0; 761];
    Small_decode(f.as_mut_ptr(), sk);
    sk = sk.offset(((761 as libc::c_int + 3 as libc::c_int) / 4 as libc::c_int) as isize);
    Small_decode(v.as_mut_ptr(), sk);
    Rounded_decode(c.as_mut_ptr(), C);
    Decrypt(r, c.as_mut_ptr(), f.as_mut_ptr(), v.as_mut_ptr());
}
unsafe extern "C" fn HashConfirm(
    mut h: *mut libc::c_uchar,
    mut r: *const libc::c_uchar,
    mut pk: *const libc::c_uchar,
    mut cache: *const libc::c_uchar,
) {
    let mut x: [libc::c_uchar; 64] = [0; 64];
    let mut i: libc::c_int = 0;
    Hash_prefix(
        x.as_mut_ptr(),
        3 as libc::c_int,
        r,
        (761 as libc::c_int + 3 as libc::c_int) / 4 as libc::c_int,
    );
    i = 0 as libc::c_int;
    while i < 32 as libc::c_int {
        x[(32 as libc::c_int + i) as usize] = *cache.offset(i as isize);
        i += 1;
        i;
    }
    Hash_prefix(
        h,
        2 as libc::c_int,
        x.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_uchar; 64]>() as libc::c_ulong as libc::c_int,
    );
}
unsafe extern "C" fn HashSession(
    mut k: *mut libc::c_uchar,
    mut b: libc::c_int,
    mut y: *const libc::c_uchar,
    mut z: *const libc::c_uchar,
) {
    let mut x: [libc::c_uchar; 1071] = [0; 1071];
    let mut i: libc::c_int = 0;
    Hash_prefix(
        x.as_mut_ptr(),
        3 as libc::c_int,
        y,
        (761 as libc::c_int + 3 as libc::c_int) / 4 as libc::c_int,
    );
    i = 0 as libc::c_int;
    while i < 1007 as libc::c_int + 32 as libc::c_int {
        x[(32 as libc::c_int + i) as usize] = *z.offset(i as isize);
        i += 1;
        i;
    }
    Hash_prefix(
        k,
        b,
        x.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_uchar; 1071]>() as libc::c_ulong as libc::c_int,
    );
}
unsafe extern "C" fn KEM_KeyGen(mut pk: *mut libc::c_uchar, mut sk: *mut libc::c_uchar) {
    let mut i: libc::c_int = 0;
    ZKeyGen(pk, sk);
    sk = sk.offset(
        (2 as libc::c_int * ((761 as libc::c_int + 3 as libc::c_int) / 4 as libc::c_int)) as isize,
    );
    i = 0 as libc::c_int;
    while i < 1158 as libc::c_int {
        let fresh28 = sk;
        sk = sk.offset(1);
        *fresh28 = *pk.offset(i as isize);
        i += 1;
        i;
    }
    arc4random_buf(
        sk as *mut libc::c_void,
        ((761 as libc::c_int + 3 as libc::c_int) / 4 as libc::c_int) as size_t,
    );
    sk = sk.offset(((761 as libc::c_int + 3 as libc::c_int) / 4 as libc::c_int) as isize);
    Hash_prefix(sk, 4 as libc::c_int, pk, 1158 as libc::c_int);
}
unsafe extern "C" fn Hide(
    mut c: *mut libc::c_uchar,
    mut r_enc: *mut libc::c_uchar,
    mut r: *const small,
    mut pk: *const libc::c_uchar,
    mut cache: *const libc::c_uchar,
) {
    Small_encode(r_enc, r);
    ZEncrypt(c, r, pk);
    c = c.offset(1007 as libc::c_int as isize);
    HashConfirm(c, r_enc, pk, cache);
}
unsafe extern "C" fn Encap(
    mut c: *mut libc::c_uchar,
    mut k: *mut libc::c_uchar,
    mut pk: *const libc::c_uchar,
) {
    let mut r: Inputs = [0; 761];
    let mut r_enc: [libc::c_uchar; 191] = [0; 191];
    let mut cache: [libc::c_uchar; 32] = [0; 32];
    Hash_prefix(
        cache.as_mut_ptr(),
        4 as libc::c_int,
        pk,
        1158 as libc::c_int,
    );
    Short_random(r.as_mut_ptr());
    Hide(
        c,
        r_enc.as_mut_ptr(),
        r.as_mut_ptr() as *const small,
        pk,
        cache.as_mut_ptr(),
    );
    HashSession(k, 1 as libc::c_int, r_enc.as_mut_ptr(), c);
}
unsafe extern "C" fn Ciphertexts_diff_mask(
    mut c: *const libc::c_uchar,
    mut c2: *const libc::c_uchar,
) -> libc::c_int {
    let mut differentbits: crypto_uint16 = 0 as libc::c_int as crypto_uint16;
    let mut len: libc::c_int = 1007 as libc::c_int + 32 as libc::c_int;
    loop {
        let fresh29 = len;
        len = len - 1;
        if !(fresh29 > 0 as libc::c_int) {
            break;
        }
        let fresh30 = c;
        c = c.offset(1);
        let fresh31 = c2;
        c2 = c2.offset(1);
        differentbits = (differentbits as libc::c_int
            | *fresh30 as libc::c_int ^ *fresh31 as libc::c_int)
            as crypto_uint16;
    }
    return (1 as libc::c_int
        & differentbits as libc::c_int - 1 as libc::c_int >> 8 as libc::c_int)
        - 1 as libc::c_int;
}
unsafe extern "C" fn Decap(
    mut k: *mut libc::c_uchar,
    mut c: *const libc::c_uchar,
    mut sk: *const libc::c_uchar,
) {
    let mut pk: *const libc::c_uchar = sk.offset(
        (2 as libc::c_int * ((761 as libc::c_int + 3 as libc::c_int) / 4 as libc::c_int)) as isize,
    );
    let mut rho: *const libc::c_uchar = pk.offset(1158 as libc::c_int as isize);
    let mut cache: *const libc::c_uchar =
        rho.offset(((761 as libc::c_int + 3 as libc::c_int) / 4 as libc::c_int) as isize);
    let mut r: Inputs = [0; 761];
    let mut r_enc: [libc::c_uchar; 191] = [0; 191];
    let mut cnew: [libc::c_uchar; 1039] = [0; 1039];
    let mut mask: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    ZDecrypt(r.as_mut_ptr(), c, sk);
    Hide(
        cnew.as_mut_ptr(),
        r_enc.as_mut_ptr(),
        r.as_mut_ptr() as *const small,
        pk,
        cache,
    );
    mask = Ciphertexts_diff_mask(c, cnew.as_mut_ptr());
    i = 0 as libc::c_int;
    while i < (761 as libc::c_int + 3 as libc::c_int) / 4 as libc::c_int {
        r_enc[i as usize] = (r_enc[i as usize] as libc::c_int
            ^ mask & (r_enc[i as usize] as libc::c_int ^ *rho.offset(i as isize) as libc::c_int))
            as libc::c_uchar;
        i += 1;
        i;
    }
    HashSession(k, 1 as libc::c_int + mask, r_enc.as_mut_ptr(), c);
}
pub unsafe extern "C" fn crypto_kem_sntrup761_keypair(
    mut pk: *mut libc::c_uchar,
    mut sk: *mut libc::c_uchar,
) -> libc::c_int {
    KEM_KeyGen(pk, sk);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn crypto_kem_sntrup761_enc(
    mut c: *mut libc::c_uchar,
    mut k: *mut libc::c_uchar,
    mut pk: *const libc::c_uchar,
) -> libc::c_int {
    Encap(c, k, pk);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn crypto_kem_sntrup761_dec(
    mut k: *mut libc::c_uchar,
    mut c: *const libc::c_uchar,
    mut sk: *const libc::c_uchar,
) -> libc::c_int {
    Decap(k, c, sk);
    return 0 as libc::c_int;
}
