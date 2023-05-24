use ::libc;
pub type __u_char = libc::c_uchar;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type u_char = __u_char;
pub type size_t = libc::c_ulong;
pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;
pub type uint64_t = __uint64_t;
pub unsafe extern "C" fn poly1305_auth(
    mut out: *mut libc::c_uchar,
    mut m: *const libc::c_uchar,
    mut inlen: size_t,
    mut key: *const libc::c_uchar,
) {
    let mut current_block: u64;
    let mut t0: uint32_t = 0;
    let mut t1: uint32_t = 0;
    let mut t2: uint32_t = 0;
    let mut t3: uint32_t = 0;
    let mut h0: uint32_t = 0;
    let mut h1: uint32_t = 0;
    let mut h2: uint32_t = 0;
    let mut h3: uint32_t = 0;
    let mut h4: uint32_t = 0;
    let mut r0: uint32_t = 0;
    let mut r1: uint32_t = 0;
    let mut r2: uint32_t = 0;
    let mut r3: uint32_t = 0;
    let mut r4: uint32_t = 0;
    let mut s1: uint32_t = 0;
    let mut s2: uint32_t = 0;
    let mut s3: uint32_t = 0;
    let mut s4: uint32_t = 0;
    let mut b: uint32_t = 0;
    let mut nb: uint32_t = 0;
    let mut j: size_t = 0;
    let mut t: [uint64_t; 5] = [0; 5];
    let mut f0: uint64_t = 0;
    let mut f1: uint64_t = 0;
    let mut f2: uint64_t = 0;
    let mut f3: uint64_t = 0;
    let mut g0: uint32_t = 0;
    let mut g1: uint32_t = 0;
    let mut g2: uint32_t = 0;
    let mut g3: uint32_t = 0;
    let mut g4: uint32_t = 0;
    let mut c: uint64_t = 0;
    let mut mp: [libc::c_uchar; 16] = [0; 16];
    t0 = *key
        .offset(0 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as uint32_t
        | (*key
            .offset(0 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as uint32_t)
            << 8 as libc::c_int
        | (*key
            .offset(0 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as uint32_t)
            << 16 as libc::c_int
        | (*key
            .offset(0 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as uint32_t)
            << 24 as libc::c_int;
    t1 = *key
        .offset(4 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as uint32_t
        | (*key
            .offset(4 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as uint32_t)
            << 8 as libc::c_int
        | (*key
            .offset(4 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as uint32_t)
            << 16 as libc::c_int
        | (*key
            .offset(4 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as uint32_t)
            << 24 as libc::c_int;
    t2 = *key
        .offset(8 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as uint32_t
        | (*key
            .offset(8 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as uint32_t)
            << 8 as libc::c_int
        | (*key
            .offset(8 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as uint32_t)
            << 16 as libc::c_int
        | (*key
            .offset(8 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as uint32_t)
            << 24 as libc::c_int;
    t3 = *key
        .offset(12 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as uint32_t
        | (*key
            .offset(12 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as uint32_t)
            << 8 as libc::c_int
        | (*key
            .offset(12 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as uint32_t)
            << 16 as libc::c_int
        | (*key
            .offset(12 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as uint32_t)
            << 24 as libc::c_int;
    r0 = t0 & 0x3ffffff as libc::c_int as libc::c_uint;
    t0 >>= 26 as libc::c_int;
    t0 |= t1 << 6 as libc::c_int;
    r1 = t0 & 0x3ffff03 as libc::c_int as libc::c_uint;
    t1 >>= 20 as libc::c_int;
    t1 |= t2 << 12 as libc::c_int;
    r2 = t1 & 0x3ffc0ff as libc::c_int as libc::c_uint;
    t2 >>= 14 as libc::c_int;
    t2 |= t3 << 18 as libc::c_int;
    r3 = t2 & 0x3f03fff as libc::c_int as libc::c_uint;
    t3 >>= 8 as libc::c_int;
    r4 = t3 & 0xfffff as libc::c_int as libc::c_uint;
    s1 = r1.wrapping_mul(5 as libc::c_int as libc::c_uint);
    s2 = r2.wrapping_mul(5 as libc::c_int as libc::c_uint);
    s3 = r3.wrapping_mul(5 as libc::c_int as libc::c_uint);
    s4 = r4.wrapping_mul(5 as libc::c_int as libc::c_uint);
    h0 = 0 as libc::c_int as uint32_t;
    h1 = 0 as libc::c_int as uint32_t;
    h2 = 0 as libc::c_int as uint32_t;
    h3 = 0 as libc::c_int as uint32_t;
    h4 = 0 as libc::c_int as uint32_t;
    if inlen < 16 as libc::c_int as libc::c_ulong {
        current_block = 14662341765712329089;
    } else {
        current_block = 5331104107471120787;
    }
    loop {
        match current_block {
            5331104107471120787 => {
                m = m.offset(16 as libc::c_int as isize);
                inlen = (inlen as libc::c_ulong).wrapping_sub(16 as libc::c_int as libc::c_ulong)
                    as size_t as size_t;
                t0 = *m
                    .offset(-(16 as libc::c_int as isize))
                    .offset(0 as libc::c_int as isize) as uint32_t
                    | (*m
                        .offset(-(16 as libc::c_int as isize))
                        .offset(1 as libc::c_int as isize) as uint32_t)
                        << 8 as libc::c_int
                    | (*m
                        .offset(-(16 as libc::c_int as isize))
                        .offset(2 as libc::c_int as isize) as uint32_t)
                        << 16 as libc::c_int
                    | (*m
                        .offset(-(16 as libc::c_int as isize))
                        .offset(3 as libc::c_int as isize) as uint32_t)
                        << 24 as libc::c_int;
                t1 = *m
                    .offset(-(12 as libc::c_int as isize))
                    .offset(0 as libc::c_int as isize) as uint32_t
                    | (*m
                        .offset(-(12 as libc::c_int as isize))
                        .offset(1 as libc::c_int as isize) as uint32_t)
                        << 8 as libc::c_int
                    | (*m
                        .offset(-(12 as libc::c_int as isize))
                        .offset(2 as libc::c_int as isize) as uint32_t)
                        << 16 as libc::c_int
                    | (*m
                        .offset(-(12 as libc::c_int as isize))
                        .offset(3 as libc::c_int as isize) as uint32_t)
                        << 24 as libc::c_int;
                t2 = *m
                    .offset(-(8 as libc::c_int as isize))
                    .offset(0 as libc::c_int as isize) as uint32_t
                    | (*m
                        .offset(-(8 as libc::c_int as isize))
                        .offset(1 as libc::c_int as isize) as uint32_t)
                        << 8 as libc::c_int
                    | (*m
                        .offset(-(8 as libc::c_int as isize))
                        .offset(2 as libc::c_int as isize) as uint32_t)
                        << 16 as libc::c_int
                    | (*m
                        .offset(-(8 as libc::c_int as isize))
                        .offset(3 as libc::c_int as isize) as uint32_t)
                        << 24 as libc::c_int;
                t3 = *m
                    .offset(-(4 as libc::c_int as isize))
                    .offset(0 as libc::c_int as isize) as uint32_t
                    | (*m
                        .offset(-(4 as libc::c_int as isize))
                        .offset(1 as libc::c_int as isize) as uint32_t)
                        << 8 as libc::c_int
                    | (*m
                        .offset(-(4 as libc::c_int as isize))
                        .offset(2 as libc::c_int as isize) as uint32_t)
                        << 16 as libc::c_int
                    | (*m
                        .offset(-(4 as libc::c_int as isize))
                        .offset(3 as libc::c_int as isize) as uint32_t)
                        << 24 as libc::c_int;
                h0 = (h0 as libc::c_uint)
                    .wrapping_add(t0 & 0x3ffffff as libc::c_int as libc::c_uint)
                    as uint32_t as uint32_t;
                h1 = (h1 as libc::c_ulong).wrapping_add(
                    ((t1 as uint64_t) << 32 as libc::c_int | t0 as libc::c_ulong)
                        >> 26 as libc::c_int
                        & 0x3ffffff as libc::c_int as libc::c_ulong,
                ) as uint32_t as uint32_t;
                h2 = (h2 as libc::c_ulong).wrapping_add(
                    ((t2 as uint64_t) << 32 as libc::c_int | t1 as libc::c_ulong)
                        >> 20 as libc::c_int
                        & 0x3ffffff as libc::c_int as libc::c_ulong,
                ) as uint32_t as uint32_t;
                h3 = (h3 as libc::c_ulong).wrapping_add(
                    ((t3 as uint64_t) << 32 as libc::c_int | t2 as libc::c_ulong)
                        >> 14 as libc::c_int
                        & 0x3ffffff as libc::c_int as libc::c_ulong,
                ) as uint32_t as uint32_t;
                h4 = (h4 as libc::c_uint).wrapping_add(
                    t3 >> 8 as libc::c_int
                        | ((1 as libc::c_int) << 24 as libc::c_int) as libc::c_uint,
                ) as uint32_t as uint32_t;
            }
            _ => {
                if inlen == 0 {
                    break;
                }
                j = 0 as libc::c_int as size_t;
                while j < inlen {
                    mp[j as usize] = *m.offset(j as isize);
                    j = j.wrapping_add(1);
                    j;
                }
                let fresh0 = j;
                j = j.wrapping_add(1);
                mp[fresh0 as usize] = 1 as libc::c_int as libc::c_uchar;
                while j < 16 as libc::c_int as libc::c_ulong {
                    mp[j as usize] = 0 as libc::c_int as libc::c_uchar;
                    j = j.wrapping_add(1);
                    j;
                }
                inlen = 0 as libc::c_int as size_t;
                t0 = *mp
                    .as_mut_ptr()
                    .offset(0 as libc::c_int as isize)
                    .offset(0 as libc::c_int as isize) as uint32_t
                    | (*mp
                        .as_mut_ptr()
                        .offset(0 as libc::c_int as isize)
                        .offset(1 as libc::c_int as isize) as uint32_t)
                        << 8 as libc::c_int
                    | (*mp
                        .as_mut_ptr()
                        .offset(0 as libc::c_int as isize)
                        .offset(2 as libc::c_int as isize) as uint32_t)
                        << 16 as libc::c_int
                    | (*mp
                        .as_mut_ptr()
                        .offset(0 as libc::c_int as isize)
                        .offset(3 as libc::c_int as isize) as uint32_t)
                        << 24 as libc::c_int;
                t1 = *mp
                    .as_mut_ptr()
                    .offset(4 as libc::c_int as isize)
                    .offset(0 as libc::c_int as isize) as uint32_t
                    | (*mp
                        .as_mut_ptr()
                        .offset(4 as libc::c_int as isize)
                        .offset(1 as libc::c_int as isize) as uint32_t)
                        << 8 as libc::c_int
                    | (*mp
                        .as_mut_ptr()
                        .offset(4 as libc::c_int as isize)
                        .offset(2 as libc::c_int as isize) as uint32_t)
                        << 16 as libc::c_int
                    | (*mp
                        .as_mut_ptr()
                        .offset(4 as libc::c_int as isize)
                        .offset(3 as libc::c_int as isize) as uint32_t)
                        << 24 as libc::c_int;
                t2 = *mp
                    .as_mut_ptr()
                    .offset(8 as libc::c_int as isize)
                    .offset(0 as libc::c_int as isize) as uint32_t
                    | (*mp
                        .as_mut_ptr()
                        .offset(8 as libc::c_int as isize)
                        .offset(1 as libc::c_int as isize) as uint32_t)
                        << 8 as libc::c_int
                    | (*mp
                        .as_mut_ptr()
                        .offset(8 as libc::c_int as isize)
                        .offset(2 as libc::c_int as isize) as uint32_t)
                        << 16 as libc::c_int
                    | (*mp
                        .as_mut_ptr()
                        .offset(8 as libc::c_int as isize)
                        .offset(3 as libc::c_int as isize) as uint32_t)
                        << 24 as libc::c_int;
                t3 = *mp
                    .as_mut_ptr()
                    .offset(12 as libc::c_int as isize)
                    .offset(0 as libc::c_int as isize) as uint32_t
                    | (*mp
                        .as_mut_ptr()
                        .offset(12 as libc::c_int as isize)
                        .offset(1 as libc::c_int as isize) as uint32_t)
                        << 8 as libc::c_int
                    | (*mp
                        .as_mut_ptr()
                        .offset(12 as libc::c_int as isize)
                        .offset(2 as libc::c_int as isize) as uint32_t)
                        << 16 as libc::c_int
                    | (*mp
                        .as_mut_ptr()
                        .offset(12 as libc::c_int as isize)
                        .offset(3 as libc::c_int as isize) as uint32_t)
                        << 24 as libc::c_int;
                h0 = (h0 as libc::c_uint)
                    .wrapping_add(t0 & 0x3ffffff as libc::c_int as libc::c_uint)
                    as uint32_t as uint32_t;
                h1 = (h1 as libc::c_ulong).wrapping_add(
                    ((t1 as uint64_t) << 32 as libc::c_int | t0 as libc::c_ulong)
                        >> 26 as libc::c_int
                        & 0x3ffffff as libc::c_int as libc::c_ulong,
                ) as uint32_t as uint32_t;
                h2 = (h2 as libc::c_ulong).wrapping_add(
                    ((t2 as uint64_t) << 32 as libc::c_int | t1 as libc::c_ulong)
                        >> 20 as libc::c_int
                        & 0x3ffffff as libc::c_int as libc::c_ulong,
                ) as uint32_t as uint32_t;
                h3 = (h3 as libc::c_ulong).wrapping_add(
                    ((t3 as uint64_t) << 32 as libc::c_int | t2 as libc::c_ulong)
                        >> 14 as libc::c_int
                        & 0x3ffffff as libc::c_int as libc::c_ulong,
                ) as uint32_t as uint32_t;
                h4 = (h4 as libc::c_uint).wrapping_add(t3 >> 8 as libc::c_int) as uint32_t
                    as uint32_t;
            }
        }
        t[0 as libc::c_int as usize] = (h0 as uint64_t)
            .wrapping_mul(r0 as libc::c_ulong)
            .wrapping_add((h1 as uint64_t).wrapping_mul(s4 as libc::c_ulong))
            .wrapping_add((h2 as uint64_t).wrapping_mul(s3 as libc::c_ulong))
            .wrapping_add((h3 as uint64_t).wrapping_mul(s2 as libc::c_ulong))
            .wrapping_add((h4 as uint64_t).wrapping_mul(s1 as libc::c_ulong));
        t[1 as libc::c_int as usize] = (h0 as uint64_t)
            .wrapping_mul(r1 as libc::c_ulong)
            .wrapping_add((h1 as uint64_t).wrapping_mul(r0 as libc::c_ulong))
            .wrapping_add((h2 as uint64_t).wrapping_mul(s4 as libc::c_ulong))
            .wrapping_add((h3 as uint64_t).wrapping_mul(s3 as libc::c_ulong))
            .wrapping_add((h4 as uint64_t).wrapping_mul(s2 as libc::c_ulong));
        t[2 as libc::c_int as usize] = (h0 as uint64_t)
            .wrapping_mul(r2 as libc::c_ulong)
            .wrapping_add((h1 as uint64_t).wrapping_mul(r1 as libc::c_ulong))
            .wrapping_add((h2 as uint64_t).wrapping_mul(r0 as libc::c_ulong))
            .wrapping_add((h3 as uint64_t).wrapping_mul(s4 as libc::c_ulong))
            .wrapping_add((h4 as uint64_t).wrapping_mul(s3 as libc::c_ulong));
        t[3 as libc::c_int as usize] = (h0 as uint64_t)
            .wrapping_mul(r3 as libc::c_ulong)
            .wrapping_add((h1 as uint64_t).wrapping_mul(r2 as libc::c_ulong))
            .wrapping_add((h2 as uint64_t).wrapping_mul(r1 as libc::c_ulong))
            .wrapping_add((h3 as uint64_t).wrapping_mul(r0 as libc::c_ulong))
            .wrapping_add((h4 as uint64_t).wrapping_mul(s4 as libc::c_ulong));
        t[4 as libc::c_int as usize] = (h0 as uint64_t)
            .wrapping_mul(r4 as libc::c_ulong)
            .wrapping_add((h1 as uint64_t).wrapping_mul(r3 as libc::c_ulong))
            .wrapping_add((h2 as uint64_t).wrapping_mul(r2 as libc::c_ulong))
            .wrapping_add((h3 as uint64_t).wrapping_mul(r1 as libc::c_ulong))
            .wrapping_add((h4 as uint64_t).wrapping_mul(r0 as libc::c_ulong));
        h0 = t[0 as libc::c_int as usize] as uint32_t & 0x3ffffff as libc::c_int as libc::c_uint;
        c = t[0 as libc::c_int as usize] >> 26 as libc::c_int;
        t[1 as libc::c_int as usize] =
            (t[1 as libc::c_int as usize] as libc::c_ulong).wrapping_add(c) as uint64_t as uint64_t;
        h1 = t[1 as libc::c_int as usize] as uint32_t & 0x3ffffff as libc::c_int as libc::c_uint;
        b = (t[1 as libc::c_int as usize] >> 26 as libc::c_int) as uint32_t;
        t[2 as libc::c_int as usize] = (t[2 as libc::c_int as usize] as libc::c_ulong)
            .wrapping_add(b as libc::c_ulong) as uint64_t
            as uint64_t;
        h2 = t[2 as libc::c_int as usize] as uint32_t & 0x3ffffff as libc::c_int as libc::c_uint;
        b = (t[2 as libc::c_int as usize] >> 26 as libc::c_int) as uint32_t;
        t[3 as libc::c_int as usize] = (t[3 as libc::c_int as usize] as libc::c_ulong)
            .wrapping_add(b as libc::c_ulong) as uint64_t
            as uint64_t;
        h3 = t[3 as libc::c_int as usize] as uint32_t & 0x3ffffff as libc::c_int as libc::c_uint;
        b = (t[3 as libc::c_int as usize] >> 26 as libc::c_int) as uint32_t;
        t[4 as libc::c_int as usize] = (t[4 as libc::c_int as usize] as libc::c_ulong)
            .wrapping_add(b as libc::c_ulong) as uint64_t
            as uint64_t;
        h4 = t[4 as libc::c_int as usize] as uint32_t & 0x3ffffff as libc::c_int as libc::c_uint;
        b = (t[4 as libc::c_int as usize] >> 26 as libc::c_int) as uint32_t;
        h0 = (h0 as libc::c_uint).wrapping_add(b.wrapping_mul(5 as libc::c_int as libc::c_uint))
            as uint32_t as uint32_t;
        if inlen >= 16 as libc::c_int as libc::c_ulong {
            current_block = 5331104107471120787;
        } else {
            current_block = 14662341765712329089;
        }
    }
    b = h0 >> 26 as libc::c_int;
    h0 = h0 & 0x3ffffff as libc::c_int as libc::c_uint;
    h1 = (h1 as libc::c_uint).wrapping_add(b) as uint32_t as uint32_t;
    b = h1 >> 26 as libc::c_int;
    h1 = h1 & 0x3ffffff as libc::c_int as libc::c_uint;
    h2 = (h2 as libc::c_uint).wrapping_add(b) as uint32_t as uint32_t;
    b = h2 >> 26 as libc::c_int;
    h2 = h2 & 0x3ffffff as libc::c_int as libc::c_uint;
    h3 = (h3 as libc::c_uint).wrapping_add(b) as uint32_t as uint32_t;
    b = h3 >> 26 as libc::c_int;
    h3 = h3 & 0x3ffffff as libc::c_int as libc::c_uint;
    h4 = (h4 as libc::c_uint).wrapping_add(b) as uint32_t as uint32_t;
    b = h4 >> 26 as libc::c_int;
    h4 = h4 & 0x3ffffff as libc::c_int as libc::c_uint;
    h0 = (h0 as libc::c_uint).wrapping_add(b.wrapping_mul(5 as libc::c_int as libc::c_uint))
        as uint32_t as uint32_t;
    b = h0 >> 26 as libc::c_int;
    h0 = h0 & 0x3ffffff as libc::c_int as libc::c_uint;
    h1 = (h1 as libc::c_uint).wrapping_add(b) as uint32_t as uint32_t;
    g0 = h0.wrapping_add(5 as libc::c_int as libc::c_uint);
    b = g0 >> 26 as libc::c_int;
    g0 &= 0x3ffffff as libc::c_int as libc::c_uint;
    g1 = h1.wrapping_add(b);
    b = g1 >> 26 as libc::c_int;
    g1 &= 0x3ffffff as libc::c_int as libc::c_uint;
    g2 = h2.wrapping_add(b);
    b = g2 >> 26 as libc::c_int;
    g2 &= 0x3ffffff as libc::c_int as libc::c_uint;
    g3 = h3.wrapping_add(b);
    b = g3 >> 26 as libc::c_int;
    g3 &= 0x3ffffff as libc::c_int as libc::c_uint;
    g4 = h4
        .wrapping_add(b)
        .wrapping_sub(((1 as libc::c_int) << 26 as libc::c_int) as libc::c_uint);
    b = (g4 >> 31 as libc::c_int).wrapping_sub(1 as libc::c_int as libc::c_uint);
    nb = !b;
    h0 = h0 & nb | g0 & b;
    h1 = h1 & nb | g1 & b;
    h2 = h2 & nb | g2 & b;
    h3 = h3 & nb | g3 & b;
    h4 = h4 & nb | g4 & b;
    f0 = ((h0 | h1 << 26 as libc::c_int) as libc::c_ulong).wrapping_add(
        (*(&*key.offset(16 as libc::c_int as isize) as *const libc::c_uchar)
            .offset(0 as libc::c_int as isize) as uint32_t
            | (*(&*key.offset(16 as libc::c_int as isize) as *const libc::c_uchar)
                .offset(1 as libc::c_int as isize) as uint32_t)
                << 8 as libc::c_int
            | (*(&*key.offset(16 as libc::c_int as isize) as *const libc::c_uchar)
                .offset(2 as libc::c_int as isize) as uint32_t)
                << 16 as libc::c_int
            | (*(&*key.offset(16 as libc::c_int as isize) as *const libc::c_uchar)
                .offset(3 as libc::c_int as isize) as uint32_t)
                << 24 as libc::c_int) as uint64_t,
    );
    f1 = ((h1 >> 6 as libc::c_int | h2 << 20 as libc::c_int) as libc::c_ulong).wrapping_add(
        (*(&*key.offset(20 as libc::c_int as isize) as *const libc::c_uchar)
            .offset(0 as libc::c_int as isize) as uint32_t
            | (*(&*key.offset(20 as libc::c_int as isize) as *const libc::c_uchar)
                .offset(1 as libc::c_int as isize) as uint32_t)
                << 8 as libc::c_int
            | (*(&*key.offset(20 as libc::c_int as isize) as *const libc::c_uchar)
                .offset(2 as libc::c_int as isize) as uint32_t)
                << 16 as libc::c_int
            | (*(&*key.offset(20 as libc::c_int as isize) as *const libc::c_uchar)
                .offset(3 as libc::c_int as isize) as uint32_t)
                << 24 as libc::c_int) as uint64_t,
    );
    f2 = ((h2 >> 12 as libc::c_int | h3 << 14 as libc::c_int) as libc::c_ulong).wrapping_add(
        (*(&*key.offset(24 as libc::c_int as isize) as *const libc::c_uchar)
            .offset(0 as libc::c_int as isize) as uint32_t
            | (*(&*key.offset(24 as libc::c_int as isize) as *const libc::c_uchar)
                .offset(1 as libc::c_int as isize) as uint32_t)
                << 8 as libc::c_int
            | (*(&*key.offset(24 as libc::c_int as isize) as *const libc::c_uchar)
                .offset(2 as libc::c_int as isize) as uint32_t)
                << 16 as libc::c_int
            | (*(&*key.offset(24 as libc::c_int as isize) as *const libc::c_uchar)
                .offset(3 as libc::c_int as isize) as uint32_t)
                << 24 as libc::c_int) as uint64_t,
    );
    f3 = ((h3 >> 18 as libc::c_int | h4 << 8 as libc::c_int) as libc::c_ulong).wrapping_add(
        (*(&*key.offset(28 as libc::c_int as isize) as *const libc::c_uchar)
            .offset(0 as libc::c_int as isize) as uint32_t
            | (*(&*key.offset(28 as libc::c_int as isize) as *const libc::c_uchar)
                .offset(1 as libc::c_int as isize) as uint32_t)
                << 8 as libc::c_int
            | (*(&*key.offset(28 as libc::c_int as isize) as *const libc::c_uchar)
                .offset(2 as libc::c_int as isize) as uint32_t)
                << 16 as libc::c_int
            | (*(&*key.offset(28 as libc::c_int as isize) as *const libc::c_uchar)
                .offset(3 as libc::c_int as isize) as uint32_t)
                << 24 as libc::c_int) as uint64_t,
    );
    *(&mut *out.offset(0 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(0 as libc::c_int as isize) = f0 as uint8_t;
    *(&mut *out.offset(0 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(1 as libc::c_int as isize) = (f0 >> 8 as libc::c_int) as uint8_t;
    *(&mut *out.offset(0 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(2 as libc::c_int as isize) = (f0 >> 16 as libc::c_int) as uint8_t;
    *(&mut *out.offset(0 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(3 as libc::c_int as isize) = (f0 >> 24 as libc::c_int) as uint8_t;
    f1 = (f1 as libc::c_ulong).wrapping_add(f0 >> 32 as libc::c_int) as uint64_t as uint64_t;
    *(&mut *out.offset(4 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(0 as libc::c_int as isize) = f1 as uint8_t;
    *(&mut *out.offset(4 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(1 as libc::c_int as isize) = (f1 >> 8 as libc::c_int) as uint8_t;
    *(&mut *out.offset(4 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(2 as libc::c_int as isize) = (f1 >> 16 as libc::c_int) as uint8_t;
    *(&mut *out.offset(4 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(3 as libc::c_int as isize) = (f1 >> 24 as libc::c_int) as uint8_t;
    f2 = (f2 as libc::c_ulong).wrapping_add(f1 >> 32 as libc::c_int) as uint64_t as uint64_t;
    *(&mut *out.offset(8 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(0 as libc::c_int as isize) = f2 as uint8_t;
    *(&mut *out.offset(8 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(1 as libc::c_int as isize) = (f2 >> 8 as libc::c_int) as uint8_t;
    *(&mut *out.offset(8 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(2 as libc::c_int as isize) = (f2 >> 16 as libc::c_int) as uint8_t;
    *(&mut *out.offset(8 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(3 as libc::c_int as isize) = (f2 >> 24 as libc::c_int) as uint8_t;
    f3 = (f3 as libc::c_ulong).wrapping_add(f2 >> 32 as libc::c_int) as uint64_t as uint64_t;
    *(&mut *out.offset(12 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(0 as libc::c_int as isize) = f3 as uint8_t;
    *(&mut *out.offset(12 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(1 as libc::c_int as isize) = (f3 >> 8 as libc::c_int) as uint8_t;
    *(&mut *out.offset(12 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(2 as libc::c_int as isize) = (f3 >> 16 as libc::c_int) as uint8_t;
    *(&mut *out.offset(12 as libc::c_int as isize) as *mut libc::c_uchar)
        .offset(3 as libc::c_int as isize) = (f3 >> 24 as libc::c_int) as uint8_t;
}
