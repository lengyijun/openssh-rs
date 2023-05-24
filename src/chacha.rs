use ::libc;
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct chacha_ctx {
    pub input: [u_int; 16],
}
pub type u32_0 = libc::c_uint;
pub type u8_0 = libc::c_uchar;
static mut sigma: [libc::c_char; 16] =
    unsafe { *::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"expand 32-byte k") };
static mut tau: [libc::c_char; 16] =
    unsafe { *::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"expand 16-byte k") };
pub unsafe extern "C" fn chacha_keysetup(
    mut x: *mut chacha_ctx,
    mut k: *const u8_0,
    mut kbits: u32_0,
) {
    let mut constants: *const libc::c_char = 0 as *const libc::c_char;
    (*x).input[4 as libc::c_int as usize] = *k
        .offset(0 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*k
            .offset(0 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*k
            .offset(0 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*k
            .offset(0 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
    (*x).input[5 as libc::c_int as usize] = *k
        .offset(4 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*k
            .offset(4 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*k
            .offset(4 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*k
            .offset(4 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
    (*x).input[6 as libc::c_int as usize] = *k
        .offset(8 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*k
            .offset(8 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*k
            .offset(8 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*k
            .offset(8 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
    (*x).input[7 as libc::c_int as usize] = *k
        .offset(12 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*k
            .offset(12 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*k
            .offset(12 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*k
            .offset(12 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
    if kbits == 256 as libc::c_int as libc::c_uint {
        k = k.offset(16 as libc::c_int as isize);
        constants = sigma.as_ptr();
    } else {
        constants = tau.as_ptr();
    }
    (*x).input[8 as libc::c_int as usize] = *k
        .offset(0 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*k
            .offset(0 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*k
            .offset(0 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*k
            .offset(0 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
    (*x).input[9 as libc::c_int as usize] = *k
        .offset(4 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*k
            .offset(4 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*k
            .offset(4 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*k
            .offset(4 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
    (*x).input[10 as libc::c_int as usize] = *k
        .offset(8 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*k
            .offset(8 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*k
            .offset(8 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*k
            .offset(8 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
    (*x).input[11 as libc::c_int as usize] = *k
        .offset(12 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*k
            .offset(12 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*k
            .offset(12 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*k
            .offset(12 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
    (*x).input[0 as libc::c_int as usize] = *constants
        .offset(0 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*constants
            .offset(0 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*constants
            .offset(0 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*constants
            .offset(0 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
    (*x).input[1 as libc::c_int as usize] = *constants
        .offset(4 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*constants
            .offset(4 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*constants
            .offset(4 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*constants
            .offset(4 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
    (*x).input[2 as libc::c_int as usize] = *constants
        .offset(8 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*constants
            .offset(8 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*constants
            .offset(8 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*constants
            .offset(8 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
    (*x).input[3 as libc::c_int as usize] = *constants
        .offset(12 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*constants
            .offset(12 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*constants
            .offset(12 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*constants
            .offset(12 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
}
pub unsafe extern "C" fn chacha_ivsetup(
    mut x: *mut chacha_ctx,
    mut iv: *const u8_0,
    mut counter: *const u8_0,
) {
    (*x).input[12 as libc::c_int as usize] = if counter.is_null() {
        0 as libc::c_int as libc::c_uint
    } else {
        *counter
            .offset(0 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) as u32_0
            | (*counter
                .offset(0 as libc::c_int as isize)
                .offset(1 as libc::c_int as isize) as u32_0)
                << 8 as libc::c_int
            | (*counter
                .offset(0 as libc::c_int as isize)
                .offset(2 as libc::c_int as isize) as u32_0)
                << 16 as libc::c_int
            | (*counter
                .offset(0 as libc::c_int as isize)
                .offset(3 as libc::c_int as isize) as u32_0)
                << 24 as libc::c_int
    };
    (*x).input[13 as libc::c_int as usize] = if counter.is_null() {
        0 as libc::c_int as libc::c_uint
    } else {
        *counter
            .offset(4 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) as u32_0
            | (*counter
                .offset(4 as libc::c_int as isize)
                .offset(1 as libc::c_int as isize) as u32_0)
                << 8 as libc::c_int
            | (*counter
                .offset(4 as libc::c_int as isize)
                .offset(2 as libc::c_int as isize) as u32_0)
                << 16 as libc::c_int
            | (*counter
                .offset(4 as libc::c_int as isize)
                .offset(3 as libc::c_int as isize) as u32_0)
                << 24 as libc::c_int
    };
    (*x).input[14 as libc::c_int as usize] = *iv
        .offset(0 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*iv
            .offset(0 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*iv
            .offset(0 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*iv
            .offset(0 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
    (*x).input[15 as libc::c_int as usize] = *iv
        .offset(4 as libc::c_int as isize)
        .offset(0 as libc::c_int as isize) as u32_0
        | (*iv
            .offset(4 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) as u32_0)
            << 8 as libc::c_int
        | (*iv
            .offset(4 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) as u32_0)
            << 16 as libc::c_int
        | (*iv
            .offset(4 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) as u32_0)
            << 24 as libc::c_int;
}
pub unsafe extern "C" fn chacha_encrypt_bytes(
    mut x: *mut chacha_ctx,
    mut m: *const u8_0,
    mut c: *mut u8_0,
    mut bytes: u32_0,
) {
    let mut x0: u32_0 = 0;
    let mut x1: u32_0 = 0;
    let mut x2: u32_0 = 0;
    let mut x3: u32_0 = 0;
    let mut x4: u32_0 = 0;
    let mut x5: u32_0 = 0;
    let mut x6: u32_0 = 0;
    let mut x7: u32_0 = 0;
    let mut x8: u32_0 = 0;
    let mut x9: u32_0 = 0;
    let mut x10: u32_0 = 0;
    let mut x11: u32_0 = 0;
    let mut x12: u32_0 = 0;
    let mut x13: u32_0 = 0;
    let mut x14: u32_0 = 0;
    let mut x15: u32_0 = 0;
    let mut j0: u32_0 = 0;
    let mut j1: u32_0 = 0;
    let mut j2: u32_0 = 0;
    let mut j3: u32_0 = 0;
    let mut j4: u32_0 = 0;
    let mut j5: u32_0 = 0;
    let mut j6: u32_0 = 0;
    let mut j7: u32_0 = 0;
    let mut j8: u32_0 = 0;
    let mut j9: u32_0 = 0;
    let mut j10: u32_0 = 0;
    let mut j11: u32_0 = 0;
    let mut j12: u32_0 = 0;
    let mut j13: u32_0 = 0;
    let mut j14: u32_0 = 0;
    let mut j15: u32_0 = 0;
    let mut ctarget: *mut u8_0 = 0 as *mut u8_0;
    let mut tmp: [u8_0; 64] = [0; 64];
    let mut i: u_int = 0;
    if bytes == 0 {
        return;
    }
    j0 = (*x).input[0 as libc::c_int as usize];
    j1 = (*x).input[1 as libc::c_int as usize];
    j2 = (*x).input[2 as libc::c_int as usize];
    j3 = (*x).input[3 as libc::c_int as usize];
    j4 = (*x).input[4 as libc::c_int as usize];
    j5 = (*x).input[5 as libc::c_int as usize];
    j6 = (*x).input[6 as libc::c_int as usize];
    j7 = (*x).input[7 as libc::c_int as usize];
    j8 = (*x).input[8 as libc::c_int as usize];
    j9 = (*x).input[9 as libc::c_int as usize];
    j10 = (*x).input[10 as libc::c_int as usize];
    j11 = (*x).input[11 as libc::c_int as usize];
    j12 = (*x).input[12 as libc::c_int as usize];
    j13 = (*x).input[13 as libc::c_int as usize];
    j14 = (*x).input[14 as libc::c_int as usize];
    j15 = (*x).input[15 as libc::c_int as usize];
    loop {
        if bytes < 64 as libc::c_int as libc::c_uint {
            i = 0 as libc::c_int as u_int;
            while i < bytes {
                tmp[i as usize] = *m.offset(i as isize);
                i = i.wrapping_add(1);
                i;
            }
            m = tmp.as_mut_ptr();
            ctarget = c;
            c = tmp.as_mut_ptr();
        }
        x0 = j0;
        x1 = j1;
        x2 = j2;
        x3 = j3;
        x4 = j4;
        x5 = j5;
        x6 = j6;
        x7 = j7;
        x8 = j8;
        x9 = j9;
        x10 = j10;
        x11 = j11;
        x12 = j12;
        x13 = j13;
        x14 = j14;
        x15 = j15;
        i = 20 as libc::c_int as u_int;
        while i > 0 as libc::c_int as libc::c_uint {
            x0 = x0.wrapping_add(x4) & 0xffffffff as libc::c_uint;
            x12 = (x12 ^ x0) << 16 as libc::c_int & 0xffffffff as libc::c_uint
                | (x12 ^ x0) >> 32 as libc::c_int - 16 as libc::c_int;
            x8 = x8.wrapping_add(x12) & 0xffffffff as libc::c_uint;
            x4 = (x4 ^ x8) << 12 as libc::c_int & 0xffffffff as libc::c_uint
                | (x4 ^ x8) >> 32 as libc::c_int - 12 as libc::c_int;
            x0 = x0.wrapping_add(x4) & 0xffffffff as libc::c_uint;
            x12 = (x12 ^ x0) << 8 as libc::c_int & 0xffffffff as libc::c_uint
                | (x12 ^ x0) >> 32 as libc::c_int - 8 as libc::c_int;
            x8 = x8.wrapping_add(x12) & 0xffffffff as libc::c_uint;
            x4 = (x4 ^ x8) << 7 as libc::c_int & 0xffffffff as libc::c_uint
                | (x4 ^ x8) >> 32 as libc::c_int - 7 as libc::c_int;
            x1 = x1.wrapping_add(x5) & 0xffffffff as libc::c_uint;
            x13 = (x13 ^ x1) << 16 as libc::c_int & 0xffffffff as libc::c_uint
                | (x13 ^ x1) >> 32 as libc::c_int - 16 as libc::c_int;
            x9 = x9.wrapping_add(x13) & 0xffffffff as libc::c_uint;
            x5 = (x5 ^ x9) << 12 as libc::c_int & 0xffffffff as libc::c_uint
                | (x5 ^ x9) >> 32 as libc::c_int - 12 as libc::c_int;
            x1 = x1.wrapping_add(x5) & 0xffffffff as libc::c_uint;
            x13 = (x13 ^ x1) << 8 as libc::c_int & 0xffffffff as libc::c_uint
                | (x13 ^ x1) >> 32 as libc::c_int - 8 as libc::c_int;
            x9 = x9.wrapping_add(x13) & 0xffffffff as libc::c_uint;
            x5 = (x5 ^ x9) << 7 as libc::c_int & 0xffffffff as libc::c_uint
                | (x5 ^ x9) >> 32 as libc::c_int - 7 as libc::c_int;
            x2 = x2.wrapping_add(x6) & 0xffffffff as libc::c_uint;
            x14 = (x14 ^ x2) << 16 as libc::c_int & 0xffffffff as libc::c_uint
                | (x14 ^ x2) >> 32 as libc::c_int - 16 as libc::c_int;
            x10 = x10.wrapping_add(x14) & 0xffffffff as libc::c_uint;
            x6 = (x6 ^ x10) << 12 as libc::c_int & 0xffffffff as libc::c_uint
                | (x6 ^ x10) >> 32 as libc::c_int - 12 as libc::c_int;
            x2 = x2.wrapping_add(x6) & 0xffffffff as libc::c_uint;
            x14 = (x14 ^ x2) << 8 as libc::c_int & 0xffffffff as libc::c_uint
                | (x14 ^ x2) >> 32 as libc::c_int - 8 as libc::c_int;
            x10 = x10.wrapping_add(x14) & 0xffffffff as libc::c_uint;
            x6 = (x6 ^ x10) << 7 as libc::c_int & 0xffffffff as libc::c_uint
                | (x6 ^ x10) >> 32 as libc::c_int - 7 as libc::c_int;
            x3 = x3.wrapping_add(x7) & 0xffffffff as libc::c_uint;
            x15 = (x15 ^ x3) << 16 as libc::c_int & 0xffffffff as libc::c_uint
                | (x15 ^ x3) >> 32 as libc::c_int - 16 as libc::c_int;
            x11 = x11.wrapping_add(x15) & 0xffffffff as libc::c_uint;
            x7 = (x7 ^ x11) << 12 as libc::c_int & 0xffffffff as libc::c_uint
                | (x7 ^ x11) >> 32 as libc::c_int - 12 as libc::c_int;
            x3 = x3.wrapping_add(x7) & 0xffffffff as libc::c_uint;
            x15 = (x15 ^ x3) << 8 as libc::c_int & 0xffffffff as libc::c_uint
                | (x15 ^ x3) >> 32 as libc::c_int - 8 as libc::c_int;
            x11 = x11.wrapping_add(x15) & 0xffffffff as libc::c_uint;
            x7 = (x7 ^ x11) << 7 as libc::c_int & 0xffffffff as libc::c_uint
                | (x7 ^ x11) >> 32 as libc::c_int - 7 as libc::c_int;
            x0 = x0.wrapping_add(x5) & 0xffffffff as libc::c_uint;
            x15 = (x15 ^ x0) << 16 as libc::c_int & 0xffffffff as libc::c_uint
                | (x15 ^ x0) >> 32 as libc::c_int - 16 as libc::c_int;
            x10 = x10.wrapping_add(x15) & 0xffffffff as libc::c_uint;
            x5 = (x5 ^ x10) << 12 as libc::c_int & 0xffffffff as libc::c_uint
                | (x5 ^ x10) >> 32 as libc::c_int - 12 as libc::c_int;
            x0 = x0.wrapping_add(x5) & 0xffffffff as libc::c_uint;
            x15 = (x15 ^ x0) << 8 as libc::c_int & 0xffffffff as libc::c_uint
                | (x15 ^ x0) >> 32 as libc::c_int - 8 as libc::c_int;
            x10 = x10.wrapping_add(x15) & 0xffffffff as libc::c_uint;
            x5 = (x5 ^ x10) << 7 as libc::c_int & 0xffffffff as libc::c_uint
                | (x5 ^ x10) >> 32 as libc::c_int - 7 as libc::c_int;
            x1 = x1.wrapping_add(x6) & 0xffffffff as libc::c_uint;
            x12 = (x12 ^ x1) << 16 as libc::c_int & 0xffffffff as libc::c_uint
                | (x12 ^ x1) >> 32 as libc::c_int - 16 as libc::c_int;
            x11 = x11.wrapping_add(x12) & 0xffffffff as libc::c_uint;
            x6 = (x6 ^ x11) << 12 as libc::c_int & 0xffffffff as libc::c_uint
                | (x6 ^ x11) >> 32 as libc::c_int - 12 as libc::c_int;
            x1 = x1.wrapping_add(x6) & 0xffffffff as libc::c_uint;
            x12 = (x12 ^ x1) << 8 as libc::c_int & 0xffffffff as libc::c_uint
                | (x12 ^ x1) >> 32 as libc::c_int - 8 as libc::c_int;
            x11 = x11.wrapping_add(x12) & 0xffffffff as libc::c_uint;
            x6 = (x6 ^ x11) << 7 as libc::c_int & 0xffffffff as libc::c_uint
                | (x6 ^ x11) >> 32 as libc::c_int - 7 as libc::c_int;
            x2 = x2.wrapping_add(x7) & 0xffffffff as libc::c_uint;
            x13 = (x13 ^ x2) << 16 as libc::c_int & 0xffffffff as libc::c_uint
                | (x13 ^ x2) >> 32 as libc::c_int - 16 as libc::c_int;
            x8 = x8.wrapping_add(x13) & 0xffffffff as libc::c_uint;
            x7 = (x7 ^ x8) << 12 as libc::c_int & 0xffffffff as libc::c_uint
                | (x7 ^ x8) >> 32 as libc::c_int - 12 as libc::c_int;
            x2 = x2.wrapping_add(x7) & 0xffffffff as libc::c_uint;
            x13 = (x13 ^ x2) << 8 as libc::c_int & 0xffffffff as libc::c_uint
                | (x13 ^ x2) >> 32 as libc::c_int - 8 as libc::c_int;
            x8 = x8.wrapping_add(x13) & 0xffffffff as libc::c_uint;
            x7 = (x7 ^ x8) << 7 as libc::c_int & 0xffffffff as libc::c_uint
                | (x7 ^ x8) >> 32 as libc::c_int - 7 as libc::c_int;
            x3 = x3.wrapping_add(x4) & 0xffffffff as libc::c_uint;
            x14 = (x14 ^ x3) << 16 as libc::c_int & 0xffffffff as libc::c_uint
                | (x14 ^ x3) >> 32 as libc::c_int - 16 as libc::c_int;
            x9 = x9.wrapping_add(x14) & 0xffffffff as libc::c_uint;
            x4 = (x4 ^ x9) << 12 as libc::c_int & 0xffffffff as libc::c_uint
                | (x4 ^ x9) >> 32 as libc::c_int - 12 as libc::c_int;
            x3 = x3.wrapping_add(x4) & 0xffffffff as libc::c_uint;
            x14 = (x14 ^ x3) << 8 as libc::c_int & 0xffffffff as libc::c_uint
                | (x14 ^ x3) >> 32 as libc::c_int - 8 as libc::c_int;
            x9 = x9.wrapping_add(x14) & 0xffffffff as libc::c_uint;
            x4 = (x4 ^ x9) << 7 as libc::c_int & 0xffffffff as libc::c_uint
                | (x4 ^ x9) >> 32 as libc::c_int - 7 as libc::c_int;
            i = (i as libc::c_uint).wrapping_sub(2 as libc::c_int as libc::c_uint) as u_int
                as u_int;
        }
        x0 = x0.wrapping_add(j0) & 0xffffffff as libc::c_uint;
        x1 = x1.wrapping_add(j1) & 0xffffffff as libc::c_uint;
        x2 = x2.wrapping_add(j2) & 0xffffffff as libc::c_uint;
        x3 = x3.wrapping_add(j3) & 0xffffffff as libc::c_uint;
        x4 = x4.wrapping_add(j4) & 0xffffffff as libc::c_uint;
        x5 = x5.wrapping_add(j5) & 0xffffffff as libc::c_uint;
        x6 = x6.wrapping_add(j6) & 0xffffffff as libc::c_uint;
        x7 = x7.wrapping_add(j7) & 0xffffffff as libc::c_uint;
        x8 = x8.wrapping_add(j8) & 0xffffffff as libc::c_uint;
        x9 = x9.wrapping_add(j9) & 0xffffffff as libc::c_uint;
        x10 = x10.wrapping_add(j10) & 0xffffffff as libc::c_uint;
        x11 = x11.wrapping_add(j11) & 0xffffffff as libc::c_uint;
        x12 = x12.wrapping_add(j12) & 0xffffffff as libc::c_uint;
        x13 = x13.wrapping_add(j13) & 0xffffffff as libc::c_uint;
        x14 = x14.wrapping_add(j14) & 0xffffffff as libc::c_uint;
        x15 = x15.wrapping_add(j15) & 0xffffffff as libc::c_uint;
        x0 = x0
            ^ (*m
                .offset(0 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(0 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(0 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(0 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x1 = x1
            ^ (*m
                .offset(4 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(4 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(4 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(4 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x2 = x2
            ^ (*m
                .offset(8 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(8 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(8 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(8 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x3 = x3
            ^ (*m
                .offset(12 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(12 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(12 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(12 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x4 = x4
            ^ (*m
                .offset(16 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(16 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(16 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(16 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x5 = x5
            ^ (*m
                .offset(20 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(20 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(20 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(20 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x6 = x6
            ^ (*m
                .offset(24 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(24 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(24 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(24 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x7 = x7
            ^ (*m
                .offset(28 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(28 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(28 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(28 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x8 = x8
            ^ (*m
                .offset(32 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(32 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(32 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(32 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x9 = x9
            ^ (*m
                .offset(36 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(36 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(36 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(36 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x10 = x10
            ^ (*m
                .offset(40 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(40 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(40 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(40 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x11 = x11
            ^ (*m
                .offset(44 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(44 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(44 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(44 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x12 = x12
            ^ (*m
                .offset(48 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(48 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(48 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(48 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x13 = x13
            ^ (*m
                .offset(52 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(52 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(52 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(52 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x14 = x14
            ^ (*m
                .offset(56 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(56 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(56 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(56 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        x15 = x15
            ^ (*m
                .offset(60 as libc::c_int as isize)
                .offset(0 as libc::c_int as isize) as u32_0
                | (*m
                    .offset(60 as libc::c_int as isize)
                    .offset(1 as libc::c_int as isize) as u32_0)
                    << 8 as libc::c_int
                | (*m
                    .offset(60 as libc::c_int as isize)
                    .offset(2 as libc::c_int as isize) as u32_0)
                    << 16 as libc::c_int
                | (*m
                    .offset(60 as libc::c_int as isize)
                    .offset(3 as libc::c_int as isize) as u32_0)
                    << 24 as libc::c_int);
        j12 = j12.wrapping_add(1 as libc::c_int as libc::c_uint) & 0xffffffff as libc::c_uint;
        if j12 == 0 {
            j13 = j13.wrapping_add(1 as libc::c_int as libc::c_uint) & 0xffffffff as libc::c_uint;
        }
        *c.offset(0 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x0 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(0 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x0 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(0 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x0 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(0 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x0 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(4 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x1 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(4 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x1 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(4 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x1 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(4 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x1 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(8 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x2 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(8 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x2 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(8 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x2 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(8 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x2 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(12 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x3 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(12 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x3 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(12 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x3 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(12 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x3 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(16 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x4 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(16 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x4 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(16 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x4 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(16 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x4 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(20 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x5 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(20 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x5 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(20 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x5 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(20 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x5 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(24 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x6 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(24 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x6 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(24 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x6 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(24 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x6 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(28 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x7 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(28 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x7 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(28 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x7 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(28 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x7 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(32 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x8 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(32 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x8 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(32 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x8 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(32 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x8 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(36 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x9 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(36 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x9 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(36 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x9 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(36 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x9 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(40 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x10 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(40 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x10 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(40 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x10 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(40 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x10 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(44 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x11 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(44 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x11 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(44 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x11 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(44 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x11 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(48 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x12 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(48 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x12 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(48 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x12 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(48 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x12 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(52 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x13 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(52 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x13 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(52 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x13 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(52 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x13 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(56 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x14 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(56 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x14 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(56 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x14 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(56 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x14 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(60 as libc::c_int as isize)
            .offset(0 as libc::c_int as isize) =
            (x15 as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(60 as libc::c_int as isize)
            .offset(1 as libc::c_int as isize) =
            ((x15 >> 8 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(60 as libc::c_int as isize)
            .offset(2 as libc::c_int as isize) =
            ((x15 >> 16 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        *c.offset(60 as libc::c_int as isize)
            .offset(3 as libc::c_int as isize) =
            ((x15 >> 24 as libc::c_int) as u8_0 as libc::c_uint & 0xff as libc::c_uint) as u8_0;
        if bytes <= 64 as libc::c_int as libc::c_uint {
            if bytes < 64 as libc::c_int as libc::c_uint {
                i = 0 as libc::c_int as u_int;
                while i < bytes {
                    *ctarget.offset(i as isize) = *c.offset(i as isize);
                    i = i.wrapping_add(1);
                    i;
                }
            }
            (*x).input[12 as libc::c_int as usize] = j12;
            (*x).input[13 as libc::c_int as usize] = j13;
            return;
        }
        bytes = (bytes as libc::c_uint).wrapping_sub(64 as libc::c_int as libc::c_uint) as u32_0
            as u32_0;
        c = c.offset(64 as libc::c_int as isize);
        m = m.offset(64 as libc::c_int as isize);
    }
}
