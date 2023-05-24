use ::libc;
unsafe extern "C" fn add(
    mut out: *mut libc::c_uint,
    mut a: *const libc::c_uint,
    mut b: *const libc::c_uint,
) {
    let mut j: libc::c_uint = 0;
    let mut u: libc::c_uint = 0;
    u = 0 as libc::c_int as libc::c_uint;
    j = 0 as libc::c_int as libc::c_uint;
    while j < 31 as libc::c_int as libc::c_uint {
        u = u.wrapping_add((*a.offset(j as isize)).wrapping_add(*b.offset(j as isize)));
        *out.offset(j as isize) = u & 255 as libc::c_int as libc::c_uint;
        u >>= 8 as libc::c_int;
        j = j.wrapping_add(1);
        j;
    }
    u = u.wrapping_add(
        (*a.offset(31 as libc::c_int as isize)).wrapping_add(*b.offset(31 as libc::c_int as isize)),
    );
    *out.offset(31 as libc::c_int as isize) = u;
}
unsafe extern "C" fn sub(
    mut out: *mut libc::c_uint,
    mut a: *const libc::c_uint,
    mut b: *const libc::c_uint,
) {
    let mut j: libc::c_uint = 0;
    let mut u: libc::c_uint = 0;
    u = 218 as libc::c_int as libc::c_uint;
    j = 0 as libc::c_int as libc::c_uint;
    while j < 31 as libc::c_int as libc::c_uint {
        u = u.wrapping_add(
            (*a.offset(j as isize))
                .wrapping_add(65280 as libc::c_int as libc::c_uint)
                .wrapping_sub(*b.offset(j as isize)),
        );
        *out.offset(j as isize) = u & 255 as libc::c_int as libc::c_uint;
        u >>= 8 as libc::c_int;
        j = j.wrapping_add(1);
        j;
    }
    u = u.wrapping_add(
        (*a.offset(31 as libc::c_int as isize)).wrapping_sub(*b.offset(31 as libc::c_int as isize)),
    );
    *out.offset(31 as libc::c_int as isize) = u;
}
unsafe extern "C" fn squeeze(mut a: *mut libc::c_uint) {
    let mut j: libc::c_uint = 0;
    let mut u: libc::c_uint = 0;
    u = 0 as libc::c_int as libc::c_uint;
    j = 0 as libc::c_int as libc::c_uint;
    while j < 31 as libc::c_int as libc::c_uint {
        u = u.wrapping_add(*a.offset(j as isize));
        *a.offset(j as isize) = u & 255 as libc::c_int as libc::c_uint;
        u >>= 8 as libc::c_int;
        j = j.wrapping_add(1);
        j;
    }
    u = u.wrapping_add(*a.offset(31 as libc::c_int as isize));
    *a.offset(31 as libc::c_int as isize) = u & 127 as libc::c_int as libc::c_uint;
    u = (19 as libc::c_int as libc::c_uint).wrapping_mul(u >> 7 as libc::c_int);
    j = 0 as libc::c_int as libc::c_uint;
    while j < 31 as libc::c_int as libc::c_uint {
        u = u.wrapping_add(*a.offset(j as isize));
        *a.offset(j as isize) = u & 255 as libc::c_int as libc::c_uint;
        u >>= 8 as libc::c_int;
        j = j.wrapping_add(1);
        j;
    }
    u = u.wrapping_add(*a.offset(31 as libc::c_int as isize));
    *a.offset(31 as libc::c_int as isize) = u;
}
static mut minusp: [libc::c_uint; 32] = [
    19 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    0 as libc::c_int as libc::c_uint,
    128 as libc::c_int as libc::c_uint,
];
unsafe extern "C" fn freeze(mut a: *mut libc::c_uint) {
    let mut aorig: [libc::c_uint; 32] = [0; 32];
    let mut j: libc::c_uint = 0;
    let mut negative: libc::c_uint = 0;
    j = 0 as libc::c_int as libc::c_uint;
    while j < 32 as libc::c_int as libc::c_uint {
        aorig[j as usize] = *a.offset(j as isize);
        j = j.wrapping_add(1);
        j;
    }
    add(a, a as *const libc::c_uint, minusp.as_ptr());
    negative = (*a.offset(31 as libc::c_int as isize) >> 7 as libc::c_int
        & 1 as libc::c_int as libc::c_uint)
        .wrapping_neg();
    j = 0 as libc::c_int as libc::c_uint;
    while j < 32 as libc::c_int as libc::c_uint {
        *a.offset(j as isize) ^= negative & (aorig[j as usize] ^ *a.offset(j as isize));
        j = j.wrapping_add(1);
        j;
    }
}
unsafe extern "C" fn mult(
    mut out: *mut libc::c_uint,
    mut a: *const libc::c_uint,
    mut b: *const libc::c_uint,
) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut u: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 32 as libc::c_int as libc::c_uint {
        u = 0 as libc::c_int as libc::c_uint;
        j = 0 as libc::c_int as libc::c_uint;
        while j <= i {
            u = u.wrapping_add(
                (*a.offset(j as isize)).wrapping_mul(*b.offset(i.wrapping_sub(j) as isize)),
            );
            j = j.wrapping_add(1);
            j;
        }
        j = i.wrapping_add(1 as libc::c_int as libc::c_uint);
        while j < 32 as libc::c_int as libc::c_uint {
            u = u.wrapping_add(
                (38 as libc::c_int as libc::c_uint)
                    .wrapping_mul(*a.offset(j as isize))
                    .wrapping_mul(
                        *b.offset(
                            i.wrapping_add(32 as libc::c_int as libc::c_uint)
                                .wrapping_sub(j) as isize,
                        ),
                    ),
            );
            j = j.wrapping_add(1);
            j;
        }
        *out.offset(i as isize) = u;
        i = i.wrapping_add(1);
        i;
    }
    squeeze(out);
}
unsafe extern "C" fn mult121665(mut out: *mut libc::c_uint, mut a: *const libc::c_uint) {
    let mut j: libc::c_uint = 0;
    let mut u: libc::c_uint = 0;
    u = 0 as libc::c_int as libc::c_uint;
    j = 0 as libc::c_int as libc::c_uint;
    while j < 31 as libc::c_int as libc::c_uint {
        u = u.wrapping_add(
            (121665 as libc::c_int as libc::c_uint).wrapping_mul(*a.offset(j as isize)),
        );
        *out.offset(j as isize) = u & 255 as libc::c_int as libc::c_uint;
        u >>= 8 as libc::c_int;
        j = j.wrapping_add(1);
        j;
    }
    u = u.wrapping_add(
        (121665 as libc::c_int as libc::c_uint).wrapping_mul(*a.offset(31 as libc::c_int as isize)),
    );
    *out.offset(31 as libc::c_int as isize) = u & 127 as libc::c_int as libc::c_uint;
    u = (19 as libc::c_int as libc::c_uint).wrapping_mul(u >> 7 as libc::c_int);
    j = 0 as libc::c_int as libc::c_uint;
    while j < 31 as libc::c_int as libc::c_uint {
        u = u.wrapping_add(*out.offset(j as isize));
        *out.offset(j as isize) = u & 255 as libc::c_int as libc::c_uint;
        u >>= 8 as libc::c_int;
        j = j.wrapping_add(1);
        j;
    }
    u = u.wrapping_add(*out.offset(j as isize));
    *out.offset(j as isize) = u;
}
unsafe extern "C" fn square(mut out: *mut libc::c_uint, mut a: *const libc::c_uint) {
    let mut i: libc::c_uint = 0;
    let mut j: libc::c_uint = 0;
    let mut u: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 32 as libc::c_int as libc::c_uint {
        u = 0 as libc::c_int as libc::c_uint;
        j = 0 as libc::c_int as libc::c_uint;
        while j < i.wrapping_sub(j) {
            u = u.wrapping_add(
                (*a.offset(j as isize)).wrapping_mul(*a.offset(i.wrapping_sub(j) as isize)),
            );
            j = j.wrapping_add(1);
            j;
        }
        j = i.wrapping_add(1 as libc::c_int as libc::c_uint);
        while j < i
            .wrapping_add(32 as libc::c_int as libc::c_uint)
            .wrapping_sub(j)
        {
            u = u.wrapping_add(
                (38 as libc::c_int as libc::c_uint)
                    .wrapping_mul(*a.offset(j as isize))
                    .wrapping_mul(
                        *a.offset(
                            i.wrapping_add(32 as libc::c_int as libc::c_uint)
                                .wrapping_sub(j) as isize,
                        ),
                    ),
            );
            j = j.wrapping_add(1);
            j;
        }
        u = u.wrapping_mul(2 as libc::c_int as libc::c_uint);
        if i & 1 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
            u = u.wrapping_add(
                (*a.offset(i.wrapping_div(2 as libc::c_int as libc::c_uint) as isize))
                    .wrapping_mul(
                        *a.offset(i.wrapping_div(2 as libc::c_int as libc::c_uint) as isize),
                    ),
            );
            u = u.wrapping_add(
                (38 as libc::c_int as libc::c_uint)
                    .wrapping_mul(
                        *a.offset(
                            i.wrapping_div(2 as libc::c_int as libc::c_uint)
                                .wrapping_add(16 as libc::c_int as libc::c_uint)
                                as isize,
                        ),
                    )
                    .wrapping_mul(
                        *a.offset(
                            i.wrapping_div(2 as libc::c_int as libc::c_uint)
                                .wrapping_add(16 as libc::c_int as libc::c_uint)
                                as isize,
                        ),
                    ),
            );
        }
        *out.offset(i as isize) = u;
        i = i.wrapping_add(1);
        i;
    }
    squeeze(out);
}
unsafe extern "C" fn select(
    mut p: *mut libc::c_uint,
    mut q: *mut libc::c_uint,
    mut r: *const libc::c_uint,
    mut s: *const libc::c_uint,
    mut b: libc::c_uint,
) {
    let mut j: libc::c_uint = 0;
    let mut t: libc::c_uint = 0;
    let mut bminus1: libc::c_uint = 0;
    bminus1 = b.wrapping_sub(1 as libc::c_int as libc::c_uint);
    j = 0 as libc::c_int as libc::c_uint;
    while j < 64 as libc::c_int as libc::c_uint {
        t = bminus1 & (*r.offset(j as isize) ^ *s.offset(j as isize));
        *p.offset(j as isize) = *s.offset(j as isize) ^ t;
        *q.offset(j as isize) = *r.offset(j as isize) ^ t;
        j = j.wrapping_add(1);
        j;
    }
}
unsafe extern "C" fn mainloop(mut work: *mut libc::c_uint, mut e: *const libc::c_uchar) {
    let mut xzm1: [libc::c_uint; 64] = [0; 64];
    let mut xzm: [libc::c_uint; 64] = [0; 64];
    let mut xzmb: [libc::c_uint; 64] = [0; 64];
    let mut xzm1b: [libc::c_uint; 64] = [0; 64];
    let mut xznb: [libc::c_uint; 64] = [0; 64];
    let mut xzn1b: [libc::c_uint; 64] = [0; 64];
    let mut a0: [libc::c_uint; 64] = [0; 64];
    let mut a1: [libc::c_uint; 64] = [0; 64];
    let mut b0: [libc::c_uint; 64] = [0; 64];
    let mut b1: [libc::c_uint; 64] = [0; 64];
    let mut c1: [libc::c_uint; 64] = [0; 64];
    let mut r: [libc::c_uint; 32] = [0; 32];
    let mut s: [libc::c_uint; 32] = [0; 32];
    let mut t: [libc::c_uint; 32] = [0; 32];
    let mut u: [libc::c_uint; 32] = [0; 32];
    let mut j: libc::c_uint = 0;
    let mut b: libc::c_uint = 0;
    let mut pos: libc::c_int = 0;
    j = 0 as libc::c_int as libc::c_uint;
    while j < 32 as libc::c_int as libc::c_uint {
        xzm1[j as usize] = *work.offset(j as isize);
        j = j.wrapping_add(1);
        j;
    }
    xzm1[32 as libc::c_int as usize] = 1 as libc::c_int as libc::c_uint;
    j = 33 as libc::c_int as libc::c_uint;
    while j < 64 as libc::c_int as libc::c_uint {
        xzm1[j as usize] = 0 as libc::c_int as libc::c_uint;
        j = j.wrapping_add(1);
        j;
    }
    xzm[0 as libc::c_int as usize] = 1 as libc::c_int as libc::c_uint;
    j = 1 as libc::c_int as libc::c_uint;
    while j < 64 as libc::c_int as libc::c_uint {
        xzm[j as usize] = 0 as libc::c_int as libc::c_uint;
        j = j.wrapping_add(1);
        j;
    }
    pos = 254 as libc::c_int;
    while pos >= 0 as libc::c_int {
        b = (*e.offset((pos / 8 as libc::c_int) as isize) as libc::c_int
            >> (pos & 7 as libc::c_int)) as libc::c_uint;
        b &= 1 as libc::c_int as libc::c_uint;
        select(
            xzmb.as_mut_ptr(),
            xzm1b.as_mut_ptr(),
            xzm.as_mut_ptr() as *const libc::c_uint,
            xzm1.as_mut_ptr() as *const libc::c_uint,
            b,
        );
        add(
            a0.as_mut_ptr(),
            xzmb.as_mut_ptr() as *const libc::c_uint,
            xzmb.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
        );
        sub(
            a0.as_mut_ptr().offset(32 as libc::c_int as isize),
            xzmb.as_mut_ptr() as *const libc::c_uint,
            xzmb.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
        );
        add(
            a1.as_mut_ptr(),
            xzm1b.as_mut_ptr() as *const libc::c_uint,
            xzm1b.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
        );
        sub(
            a1.as_mut_ptr().offset(32 as libc::c_int as isize),
            xzm1b.as_mut_ptr() as *const libc::c_uint,
            xzm1b.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
        );
        square(b0.as_mut_ptr(), a0.as_mut_ptr() as *const libc::c_uint);
        square(
            b0.as_mut_ptr().offset(32 as libc::c_int as isize),
            a0.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
        );
        mult(
            b1.as_mut_ptr(),
            a1.as_mut_ptr() as *const libc::c_uint,
            a0.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
        );
        mult(
            b1.as_mut_ptr().offset(32 as libc::c_int as isize),
            a1.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
            a0.as_mut_ptr() as *const libc::c_uint,
        );
        add(
            c1.as_mut_ptr(),
            b1.as_mut_ptr() as *const libc::c_uint,
            b1.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
        );
        sub(
            c1.as_mut_ptr().offset(32 as libc::c_int as isize),
            b1.as_mut_ptr() as *const libc::c_uint,
            b1.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
        );
        square(
            r.as_mut_ptr(),
            c1.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
        );
        sub(
            s.as_mut_ptr(),
            b0.as_mut_ptr() as *const libc::c_uint,
            b0.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
        );
        mult121665(t.as_mut_ptr(), s.as_mut_ptr() as *const libc::c_uint);
        add(
            u.as_mut_ptr(),
            t.as_mut_ptr() as *const libc::c_uint,
            b0.as_mut_ptr() as *const libc::c_uint,
        );
        mult(
            xznb.as_mut_ptr(),
            b0.as_mut_ptr() as *const libc::c_uint,
            b0.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
        );
        mult(
            xznb.as_mut_ptr().offset(32 as libc::c_int as isize),
            s.as_mut_ptr() as *const libc::c_uint,
            u.as_mut_ptr() as *const libc::c_uint,
        );
        square(xzn1b.as_mut_ptr(), c1.as_mut_ptr() as *const libc::c_uint);
        mult(
            xzn1b.as_mut_ptr().offset(32 as libc::c_int as isize),
            r.as_mut_ptr() as *const libc::c_uint,
            work as *const libc::c_uint,
        );
        select(
            xzm.as_mut_ptr(),
            xzm1.as_mut_ptr(),
            xznb.as_mut_ptr() as *const libc::c_uint,
            xzn1b.as_mut_ptr() as *const libc::c_uint,
            b,
        );
        pos -= 1;
        pos;
    }
    j = 0 as libc::c_int as libc::c_uint;
    while j < 64 as libc::c_int as libc::c_uint {
        *work.offset(j as isize) = xzm[j as usize];
        j = j.wrapping_add(1);
        j;
    }
}
unsafe extern "C" fn recip(mut out: *mut libc::c_uint, mut z: *const libc::c_uint) {
    let mut z2: [libc::c_uint; 32] = [0; 32];
    let mut z9: [libc::c_uint; 32] = [0; 32];
    let mut z11: [libc::c_uint; 32] = [0; 32];
    let mut z2_5_0: [libc::c_uint; 32] = [0; 32];
    let mut z2_10_0: [libc::c_uint; 32] = [0; 32];
    let mut z2_20_0: [libc::c_uint; 32] = [0; 32];
    let mut z2_50_0: [libc::c_uint; 32] = [0; 32];
    let mut z2_100_0: [libc::c_uint; 32] = [0; 32];
    let mut t0: [libc::c_uint; 32] = [0; 32];
    let mut t1: [libc::c_uint; 32] = [0; 32];
    let mut i: libc::c_int = 0;
    square(z2.as_mut_ptr(), z);
    square(t1.as_mut_ptr(), z2.as_mut_ptr() as *const libc::c_uint);
    square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
    mult(z9.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint, z);
    mult(
        z11.as_mut_ptr(),
        z9.as_mut_ptr() as *const libc::c_uint,
        z2.as_mut_ptr() as *const libc::c_uint,
    );
    square(t0.as_mut_ptr(), z11.as_mut_ptr() as *const libc::c_uint);
    mult(
        z2_5_0.as_mut_ptr(),
        t0.as_mut_ptr() as *const libc::c_uint,
        z9.as_mut_ptr() as *const libc::c_uint,
    );
    square(t0.as_mut_ptr(), z2_5_0.as_mut_ptr() as *const libc::c_uint);
    square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
    square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
    square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
    square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
    mult(
        z2_10_0.as_mut_ptr(),
        t0.as_mut_ptr() as *const libc::c_uint,
        z2_5_0.as_mut_ptr() as *const libc::c_uint,
    );
    square(t0.as_mut_ptr(), z2_10_0.as_mut_ptr() as *const libc::c_uint);
    square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
    i = 2 as libc::c_int;
    while i < 10 as libc::c_int {
        square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
        square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
        i += 2 as libc::c_int;
    }
    mult(
        z2_20_0.as_mut_ptr(),
        t1.as_mut_ptr() as *const libc::c_uint,
        z2_10_0.as_mut_ptr() as *const libc::c_uint,
    );
    square(t0.as_mut_ptr(), z2_20_0.as_mut_ptr() as *const libc::c_uint);
    square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
    i = 2 as libc::c_int;
    while i < 20 as libc::c_int {
        square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
        square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
        i += 2 as libc::c_int;
    }
    mult(
        t0.as_mut_ptr(),
        t1.as_mut_ptr() as *const libc::c_uint,
        z2_20_0.as_mut_ptr() as *const libc::c_uint,
    );
    square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
    square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
    i = 2 as libc::c_int;
    while i < 10 as libc::c_int {
        square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
        square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
        i += 2 as libc::c_int;
    }
    mult(
        z2_50_0.as_mut_ptr(),
        t0.as_mut_ptr() as *const libc::c_uint,
        z2_10_0.as_mut_ptr() as *const libc::c_uint,
    );
    square(t0.as_mut_ptr(), z2_50_0.as_mut_ptr() as *const libc::c_uint);
    square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
    i = 2 as libc::c_int;
    while i < 50 as libc::c_int {
        square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
        square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
        i += 2 as libc::c_int;
    }
    mult(
        z2_100_0.as_mut_ptr(),
        t1.as_mut_ptr() as *const libc::c_uint,
        z2_50_0.as_mut_ptr() as *const libc::c_uint,
    );
    square(
        t1.as_mut_ptr(),
        z2_100_0.as_mut_ptr() as *const libc::c_uint,
    );
    square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
    i = 2 as libc::c_int;
    while i < 100 as libc::c_int {
        square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
        square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
        i += 2 as libc::c_int;
    }
    mult(
        t1.as_mut_ptr(),
        t0.as_mut_ptr() as *const libc::c_uint,
        z2_100_0.as_mut_ptr() as *const libc::c_uint,
    );
    square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
    square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
    i = 2 as libc::c_int;
    while i < 50 as libc::c_int {
        square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
        square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
        i += 2 as libc::c_int;
    }
    mult(
        t0.as_mut_ptr(),
        t1.as_mut_ptr() as *const libc::c_uint,
        z2_50_0.as_mut_ptr() as *const libc::c_uint,
    );
    square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
    square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
    square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
    square(t0.as_mut_ptr(), t1.as_mut_ptr() as *const libc::c_uint);
    square(t1.as_mut_ptr(), t0.as_mut_ptr() as *const libc::c_uint);
    mult(
        out,
        t1.as_mut_ptr() as *const libc::c_uint,
        z11.as_mut_ptr() as *const libc::c_uint,
    );
}
pub unsafe extern "C" fn crypto_scalarmult_curve25519(
    mut q: *mut libc::c_uchar,
    mut n: *const libc::c_uchar,
    mut p: *const libc::c_uchar,
) -> libc::c_int {
    let mut work: [libc::c_uint; 96] = [0; 96];
    let mut e: [libc::c_uchar; 32] = [0; 32];
    let mut i: libc::c_uint = 0;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 32 as libc::c_int as libc::c_uint {
        e[i as usize] = *n.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    e[0 as libc::c_int as usize] =
        (e[0 as libc::c_int as usize] as libc::c_int & 248 as libc::c_int) as libc::c_uchar;
    e[31 as libc::c_int as usize] =
        (e[31 as libc::c_int as usize] as libc::c_int & 127 as libc::c_int) as libc::c_uchar;
    e[31 as libc::c_int as usize] =
        (e[31 as libc::c_int as usize] as libc::c_int | 64 as libc::c_int) as libc::c_uchar;
    i = 0 as libc::c_int as libc::c_uint;
    while i < 32 as libc::c_int as libc::c_uint {
        work[i as usize] = *p.offset(i as isize) as libc::c_uint;
        i = i.wrapping_add(1);
        i;
    }
    mainloop(work.as_mut_ptr(), e.as_mut_ptr() as *const libc::c_uchar);
    recip(
        work.as_mut_ptr().offset(32 as libc::c_int as isize),
        work.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
    );
    mult(
        work.as_mut_ptr().offset(64 as libc::c_int as isize),
        work.as_mut_ptr() as *const libc::c_uint,
        work.as_mut_ptr().offset(32 as libc::c_int as isize) as *const libc::c_uint,
    );
    freeze(work.as_mut_ptr().offset(64 as libc::c_int as isize));
    i = 0 as libc::c_int as libc::c_uint;
    while i < 32 as libc::c_int as libc::c_uint {
        *q.offset(i as isize) =
            work[(64 as libc::c_int as libc::c_uint).wrapping_add(i) as usize] as libc::c_uchar;
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
