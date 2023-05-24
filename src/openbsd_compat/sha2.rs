use ::libc;
extern "C" {
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type size_t = libc::c_ulong;
pub type u_int8_t = __uint8_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _SHA2_CTX {
    pub state: C2RustUnnamed,
    pub bitcount: [u_int64_t; 2],
    pub buffer: [u_int8_t; 128],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub st32: [u_int32_t; 8],
    pub st64: [u_int64_t; 8],
}
pub type SHA2_CTX = _SHA2_CTX;
static mut K256: [u_int32_t; 64] = [
    0x428a2f98 as libc::c_ulong as u_int32_t,
    0x71374491 as libc::c_ulong as u_int32_t,
    0xb5c0fbcf as libc::c_ulong as u_int32_t,
    0xe9b5dba5 as libc::c_ulong as u_int32_t,
    0x3956c25b as libc::c_ulong as u_int32_t,
    0x59f111f1 as libc::c_ulong as u_int32_t,
    0x923f82a4 as libc::c_ulong as u_int32_t,
    0xab1c5ed5 as libc::c_ulong as u_int32_t,
    0xd807aa98 as libc::c_ulong as u_int32_t,
    0x12835b01 as libc::c_ulong as u_int32_t,
    0x243185be as libc::c_ulong as u_int32_t,
    0x550c7dc3 as libc::c_ulong as u_int32_t,
    0x72be5d74 as libc::c_ulong as u_int32_t,
    0x80deb1fe as libc::c_ulong as u_int32_t,
    0x9bdc06a7 as libc::c_ulong as u_int32_t,
    0xc19bf174 as libc::c_ulong as u_int32_t,
    0xe49b69c1 as libc::c_ulong as u_int32_t,
    0xefbe4786 as libc::c_ulong as u_int32_t,
    0xfc19dc6 as libc::c_ulong as u_int32_t,
    0x240ca1cc as libc::c_ulong as u_int32_t,
    0x2de92c6f as libc::c_ulong as u_int32_t,
    0x4a7484aa as libc::c_ulong as u_int32_t,
    0x5cb0a9dc as libc::c_ulong as u_int32_t,
    0x76f988da as libc::c_ulong as u_int32_t,
    0x983e5152 as libc::c_ulong as u_int32_t,
    0xa831c66d as libc::c_ulong as u_int32_t,
    0xb00327c8 as libc::c_ulong as u_int32_t,
    0xbf597fc7 as libc::c_ulong as u_int32_t,
    0xc6e00bf3 as libc::c_ulong as u_int32_t,
    0xd5a79147 as libc::c_ulong as u_int32_t,
    0x6ca6351 as libc::c_ulong as u_int32_t,
    0x14292967 as libc::c_ulong as u_int32_t,
    0x27b70a85 as libc::c_ulong as u_int32_t,
    0x2e1b2138 as libc::c_ulong as u_int32_t,
    0x4d2c6dfc as libc::c_ulong as u_int32_t,
    0x53380d13 as libc::c_ulong as u_int32_t,
    0x650a7354 as libc::c_ulong as u_int32_t,
    0x766a0abb as libc::c_ulong as u_int32_t,
    0x81c2c92e as libc::c_ulong as u_int32_t,
    0x92722c85 as libc::c_ulong as u_int32_t,
    0xa2bfe8a1 as libc::c_ulong as u_int32_t,
    0xa81a664b as libc::c_ulong as u_int32_t,
    0xc24b8b70 as libc::c_ulong as u_int32_t,
    0xc76c51a3 as libc::c_ulong as u_int32_t,
    0xd192e819 as libc::c_ulong as u_int32_t,
    0xd6990624 as libc::c_ulong as u_int32_t,
    0xf40e3585 as libc::c_ulong as u_int32_t,
    0x106aa070 as libc::c_ulong as u_int32_t,
    0x19a4c116 as libc::c_ulong as u_int32_t,
    0x1e376c08 as libc::c_ulong as u_int32_t,
    0x2748774c as libc::c_ulong as u_int32_t,
    0x34b0bcb5 as libc::c_ulong as u_int32_t,
    0x391c0cb3 as libc::c_ulong as u_int32_t,
    0x4ed8aa4a as libc::c_ulong as u_int32_t,
    0x5b9cca4f as libc::c_ulong as u_int32_t,
    0x682e6ff3 as libc::c_ulong as u_int32_t,
    0x748f82ee as libc::c_ulong as u_int32_t,
    0x78a5636f as libc::c_ulong as u_int32_t,
    0x84c87814 as libc::c_ulong as u_int32_t,
    0x8cc70208 as libc::c_ulong as u_int32_t,
    0x90befffa as libc::c_ulong as u_int32_t,
    0xa4506ceb as libc::c_ulong as u_int32_t,
    0xbef9a3f7 as libc::c_ulong as u_int32_t,
    0xc67178f2 as libc::c_ulong as u_int32_t,
];
static mut sha256_initial_hash_value: [u_int32_t; 8] = [
    0x6a09e667 as libc::c_ulong as u_int32_t,
    0xbb67ae85 as libc::c_ulong as u_int32_t,
    0x3c6ef372 as libc::c_ulong as u_int32_t,
    0xa54ff53a as libc::c_ulong as u_int32_t,
    0x510e527f as libc::c_ulong as u_int32_t,
    0x9b05688c as libc::c_ulong as u_int32_t,
    0x1f83d9ab as libc::c_ulong as u_int32_t,
    0x5be0cd19 as libc::c_ulong as u_int32_t,
];
static mut K512: [u_int64_t; 80] = [
    0x428a2f98d728ae22 as libc::c_ulonglong as u_int64_t,
    0x7137449123ef65cd as libc::c_ulonglong as u_int64_t,
    0xb5c0fbcfec4d3b2f as libc::c_ulonglong as u_int64_t,
    0xe9b5dba58189dbbc as libc::c_ulonglong as u_int64_t,
    0x3956c25bf348b538 as libc::c_ulonglong as u_int64_t,
    0x59f111f1b605d019 as libc::c_ulonglong as u_int64_t,
    0x923f82a4af194f9b as libc::c_ulonglong as u_int64_t,
    0xab1c5ed5da6d8118 as libc::c_ulonglong as u_int64_t,
    0xd807aa98a3030242 as libc::c_ulonglong as u_int64_t,
    0x12835b0145706fbe as libc::c_ulonglong as u_int64_t,
    0x243185be4ee4b28c as libc::c_ulonglong as u_int64_t,
    0x550c7dc3d5ffb4e2 as libc::c_ulonglong as u_int64_t,
    0x72be5d74f27b896f as libc::c_ulonglong as u_int64_t,
    0x80deb1fe3b1696b1 as libc::c_ulonglong as u_int64_t,
    0x9bdc06a725c71235 as libc::c_ulonglong as u_int64_t,
    0xc19bf174cf692694 as libc::c_ulonglong as u_int64_t,
    0xe49b69c19ef14ad2 as libc::c_ulonglong as u_int64_t,
    0xefbe4786384f25e3 as libc::c_ulonglong as u_int64_t,
    0xfc19dc68b8cd5b5 as libc::c_ulonglong as u_int64_t,
    0x240ca1cc77ac9c65 as libc::c_ulonglong as u_int64_t,
    0x2de92c6f592b0275 as libc::c_ulonglong as u_int64_t,
    0x4a7484aa6ea6e483 as libc::c_ulonglong as u_int64_t,
    0x5cb0a9dcbd41fbd4 as libc::c_ulonglong as u_int64_t,
    0x76f988da831153b5 as libc::c_ulonglong as u_int64_t,
    0x983e5152ee66dfab as libc::c_ulonglong as u_int64_t,
    0xa831c66d2db43210 as libc::c_ulonglong as u_int64_t,
    0xb00327c898fb213f as libc::c_ulonglong as u_int64_t,
    0xbf597fc7beef0ee4 as libc::c_ulonglong as u_int64_t,
    0xc6e00bf33da88fc2 as libc::c_ulonglong as u_int64_t,
    0xd5a79147930aa725 as libc::c_ulonglong as u_int64_t,
    0x6ca6351e003826f as libc::c_ulonglong as u_int64_t,
    0x142929670a0e6e70 as libc::c_ulonglong as u_int64_t,
    0x27b70a8546d22ffc as libc::c_ulonglong as u_int64_t,
    0x2e1b21385c26c926 as libc::c_ulonglong as u_int64_t,
    0x4d2c6dfc5ac42aed as libc::c_ulonglong as u_int64_t,
    0x53380d139d95b3df as libc::c_ulonglong as u_int64_t,
    0x650a73548baf63de as libc::c_ulonglong as u_int64_t,
    0x766a0abb3c77b2a8 as libc::c_ulonglong as u_int64_t,
    0x81c2c92e47edaee6 as libc::c_ulonglong as u_int64_t,
    0x92722c851482353b as libc::c_ulonglong as u_int64_t,
    0xa2bfe8a14cf10364 as libc::c_ulonglong as u_int64_t,
    0xa81a664bbc423001 as libc::c_ulonglong as u_int64_t,
    0xc24b8b70d0f89791 as libc::c_ulonglong as u_int64_t,
    0xc76c51a30654be30 as libc::c_ulonglong as u_int64_t,
    0xd192e819d6ef5218 as libc::c_ulonglong as u_int64_t,
    0xd69906245565a910 as libc::c_ulonglong as u_int64_t,
    0xf40e35855771202a as libc::c_ulonglong as u_int64_t,
    0x106aa07032bbd1b8 as libc::c_ulonglong as u_int64_t,
    0x19a4c116b8d2d0c8 as libc::c_ulonglong as u_int64_t,
    0x1e376c085141ab53 as libc::c_ulonglong as u_int64_t,
    0x2748774cdf8eeb99 as libc::c_ulonglong as u_int64_t,
    0x34b0bcb5e19b48a8 as libc::c_ulonglong as u_int64_t,
    0x391c0cb3c5c95a63 as libc::c_ulonglong as u_int64_t,
    0x4ed8aa4ae3418acb as libc::c_ulonglong as u_int64_t,
    0x5b9cca4f7763e373 as libc::c_ulonglong as u_int64_t,
    0x682e6ff3d6b2b8a3 as libc::c_ulonglong as u_int64_t,
    0x748f82ee5defb2fc as libc::c_ulonglong as u_int64_t,
    0x78a5636f43172f60 as libc::c_ulonglong as u_int64_t,
    0x84c87814a1f0ab72 as libc::c_ulonglong as u_int64_t,
    0x8cc702081a6439ec as libc::c_ulonglong as u_int64_t,
    0x90befffa23631e28 as libc::c_ulonglong as u_int64_t,
    0xa4506cebde82bde9 as libc::c_ulonglong as u_int64_t,
    0xbef9a3f7b2c67915 as libc::c_ulonglong as u_int64_t,
    0xc67178f2e372532b as libc::c_ulonglong as u_int64_t,
    0xca273eceea26619c as libc::c_ulonglong as u_int64_t,
    0xd186b8c721c0c207 as libc::c_ulonglong as u_int64_t,
    0xeada7dd6cde0eb1e as libc::c_ulonglong as u_int64_t,
    0xf57d4f7fee6ed178 as libc::c_ulonglong as u_int64_t,
    0x6f067aa72176fba as libc::c_ulonglong as u_int64_t,
    0xa637dc5a2c898a6 as libc::c_ulonglong as u_int64_t,
    0x113f9804bef90dae as libc::c_ulonglong as u_int64_t,
    0x1b710b35131c471b as libc::c_ulonglong as u_int64_t,
    0x28db77f523047d84 as libc::c_ulonglong as u_int64_t,
    0x32caab7b40c72493 as libc::c_ulonglong as u_int64_t,
    0x3c9ebe0a15c9bebc as libc::c_ulonglong as u_int64_t,
    0x431d67c49c100d4c as libc::c_ulonglong as u_int64_t,
    0x4cc5d4becb3e42b6 as libc::c_ulonglong as u_int64_t,
    0x597f299cfc657e2a as libc::c_ulonglong as u_int64_t,
    0x5fcb6fab3ad6faec as libc::c_ulonglong as u_int64_t,
    0x6c44198c4a475817 as libc::c_ulonglong as u_int64_t,
];
static mut sha512_initial_hash_value: [u_int64_t; 8] = [
    0x6a09e667f3bcc908 as libc::c_ulonglong as u_int64_t,
    0xbb67ae8584caa73b as libc::c_ulonglong as u_int64_t,
    0x3c6ef372fe94f82b as libc::c_ulonglong as u_int64_t,
    0xa54ff53a5f1d36f1 as libc::c_ulonglong as u_int64_t,
    0x510e527fade682d1 as libc::c_ulonglong as u_int64_t,
    0x9b05688c2b3e6c1f as libc::c_ulonglong as u_int64_t,
    0x1f83d9abfb41bd6b as libc::c_ulonglong as u_int64_t,
    0x5be0cd19137e2179 as libc::c_ulonglong as u_int64_t,
];
static mut sha384_initial_hash_value: [u_int64_t; 8] = [
    0xcbbb9d5dc1059ed8 as libc::c_ulonglong as u_int64_t,
    0x629a292a367cd507 as libc::c_ulonglong as u_int64_t,
    0x9159015a3070dd17 as libc::c_ulonglong as u_int64_t,
    0x152fecd8f70e5939 as libc::c_ulonglong as u_int64_t,
    0x67332667ffc00b31 as libc::c_ulonglong as u_int64_t,
    0x8eb44a8768581511 as libc::c_ulonglong as u_int64_t,
    0xdb0c2e0d64f98fa7 as libc::c_ulonglong as u_int64_t,
    0x47b5481dbefa4fa4 as libc::c_ulonglong as u_int64_t,
];
#[no_mangle]
pub unsafe extern "C" fn SHA256Init(mut context: *mut SHA2_CTX) {
    memcpy(
        ((*context).state.st32).as_mut_ptr() as *mut libc::c_void,
        sha256_initial_hash_value.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[u_int32_t; 8]>() as libc::c_ulong,
    );
    memset(
        ((*context).buffer).as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[u_int8_t; 128]>() as libc::c_ulong,
    );
    (*context).bitcount[0 as libc::c_int as usize] = 0 as libc::c_int as u_int64_t;
}
#[no_mangle]
pub unsafe extern "C" fn SHA256Transform(mut state: *mut u_int32_t, mut data: *const u_int8_t) {
    let mut a: u_int32_t = 0;
    let mut b: u_int32_t = 0;
    let mut c: u_int32_t = 0;
    let mut d: u_int32_t = 0;
    let mut e: u_int32_t = 0;
    let mut f: u_int32_t = 0;
    let mut g: u_int32_t = 0;
    let mut h: u_int32_t = 0;
    let mut s0: u_int32_t = 0;
    let mut s1: u_int32_t = 0;
    let mut T1: u_int32_t = 0;
    let mut W256: [u_int32_t; 16] = [0; 16];
    let mut j: libc::c_int = 0;
    a = *state.offset(0 as libc::c_int as isize);
    b = *state.offset(1 as libc::c_int as isize);
    c = *state.offset(2 as libc::c_int as isize);
    d = *state.offset(3 as libc::c_int as isize);
    e = *state.offset(4 as libc::c_int as isize);
    f = *state.offset(5 as libc::c_int as isize);
    g = *state.offset(6 as libc::c_int as isize);
    h = *state.offset(7 as libc::c_int as isize);
    j = 0 as libc::c_int;
    loop {
        W256[j as usize] = *data.offset(3 as libc::c_int as isize) as u_int32_t
            | (*data.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int;
        data = data.offset(4 as libc::c_int as isize);
        T1 = h
            .wrapping_add(
                (e >> 6 as libc::c_int | e << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (e >> 11 as libc::c_int | e << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (e >> 25 as libc::c_int | e << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(e & f ^ !e & g)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[j as usize]);
        d = (d as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        h = T1
            .wrapping_add(
                (a >> 2 as libc::c_int | a << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (a >> 13 as libc::c_int | a << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (a >> 22 as libc::c_int | a << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(a & b ^ a & c ^ b & c);
        j += 1;
        j;
        W256[j as usize] = *data.offset(3 as libc::c_int as isize) as u_int32_t
            | (*data.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int;
        data = data.offset(4 as libc::c_int as isize);
        T1 = g
            .wrapping_add(
                (d >> 6 as libc::c_int | d << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (d >> 11 as libc::c_int | d << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (d >> 25 as libc::c_int | d << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(d & e ^ !d & f)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[j as usize]);
        c = (c as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        g = T1
            .wrapping_add(
                (h >> 2 as libc::c_int | h << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (h >> 13 as libc::c_int | h << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (h >> 22 as libc::c_int | h << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(h & a ^ h & b ^ a & b);
        j += 1;
        j;
        W256[j as usize] = *data.offset(3 as libc::c_int as isize) as u_int32_t
            | (*data.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int;
        data = data.offset(4 as libc::c_int as isize);
        T1 = f
            .wrapping_add(
                (c >> 6 as libc::c_int | c << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (c >> 11 as libc::c_int | c << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (c >> 25 as libc::c_int | c << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(c & d ^ !c & e)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[j as usize]);
        b = (b as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        f = T1
            .wrapping_add(
                (g >> 2 as libc::c_int | g << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (g >> 13 as libc::c_int | g << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (g >> 22 as libc::c_int | g << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(g & h ^ g & a ^ h & a);
        j += 1;
        j;
        W256[j as usize] = *data.offset(3 as libc::c_int as isize) as u_int32_t
            | (*data.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int;
        data = data.offset(4 as libc::c_int as isize);
        T1 = e
            .wrapping_add(
                (b >> 6 as libc::c_int | b << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (b >> 11 as libc::c_int | b << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (b >> 25 as libc::c_int | b << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(b & c ^ !b & d)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[j as usize]);
        a = (a as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        e = T1
            .wrapping_add(
                (f >> 2 as libc::c_int | f << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (f >> 13 as libc::c_int | f << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (f >> 22 as libc::c_int | f << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(f & g ^ f & h ^ g & h);
        j += 1;
        j;
        W256[j as usize] = *data.offset(3 as libc::c_int as isize) as u_int32_t
            | (*data.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int;
        data = data.offset(4 as libc::c_int as isize);
        T1 = d
            .wrapping_add(
                (a >> 6 as libc::c_int | a << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (a >> 11 as libc::c_int | a << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (a >> 25 as libc::c_int | a << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(a & b ^ !a & c)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[j as usize]);
        h = (h as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        d = T1
            .wrapping_add(
                (e >> 2 as libc::c_int | e << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (e >> 13 as libc::c_int | e << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (e >> 22 as libc::c_int | e << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(e & f ^ e & g ^ f & g);
        j += 1;
        j;
        W256[j as usize] = *data.offset(3 as libc::c_int as isize) as u_int32_t
            | (*data.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int;
        data = data.offset(4 as libc::c_int as isize);
        T1 = c
            .wrapping_add(
                (h >> 6 as libc::c_int | h << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (h >> 11 as libc::c_int | h << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (h >> 25 as libc::c_int | h << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(h & a ^ !h & b)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[j as usize]);
        g = (g as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        c = T1
            .wrapping_add(
                (d >> 2 as libc::c_int | d << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (d >> 13 as libc::c_int | d << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (d >> 22 as libc::c_int | d << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(d & e ^ d & f ^ e & f);
        j += 1;
        j;
        W256[j as usize] = *data.offset(3 as libc::c_int as isize) as u_int32_t
            | (*data.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int;
        data = data.offset(4 as libc::c_int as isize);
        T1 = b
            .wrapping_add(
                (g >> 6 as libc::c_int | g << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (g >> 11 as libc::c_int | g << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (g >> 25 as libc::c_int | g << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(g & h ^ !g & a)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[j as usize]);
        f = (f as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        b = T1
            .wrapping_add(
                (c >> 2 as libc::c_int | c << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (c >> 13 as libc::c_int | c << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (c >> 22 as libc::c_int | c << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(c & d ^ c & e ^ d & e);
        j += 1;
        j;
        W256[j as usize] = *data.offset(3 as libc::c_int as isize) as u_int32_t
            | (*data.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int32_t) << 24 as libc::c_int;
        data = data.offset(4 as libc::c_int as isize);
        T1 = a
            .wrapping_add(
                (f >> 6 as libc::c_int | f << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (f >> 11 as libc::c_int | f << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (f >> 25 as libc::c_int | f << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(f & g ^ !f & h)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[j as usize]);
        e = (e as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        a = T1
            .wrapping_add(
                (b >> 2 as libc::c_int | b << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (b >> 13 as libc::c_int | b << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (b >> 22 as libc::c_int | b << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(b & c ^ b & d ^ c & d);
        j += 1;
        j;
        if !(j < 16 as libc::c_int) {
            break;
        }
    }
    loop {
        s0 = W256[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 7 as libc::c_int | s0 << 32 as libc::c_int - 7 as libc::c_int)
            ^ (s0 >> 18 as libc::c_int | s0 << 32 as libc::c_int - 18 as libc::c_int)
            ^ s0 >> 3 as libc::c_int;
        s1 = W256[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 17 as libc::c_int | s1 << 32 as libc::c_int - 17 as libc::c_int)
            ^ (s1 >> 19 as libc::c_int | s1 << 32 as libc::c_int - 19 as libc::c_int)
            ^ s1 >> 10 as libc::c_int;
        W256[(j & 0xf as libc::c_int) as usize] =
            (W256[(j & 0xf as libc::c_int) as usize] as libc::c_uint).wrapping_add(
                s1.wrapping_add(W256[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int32_t as u_int32_t;
        T1 = h
            .wrapping_add(
                (e >> 6 as libc::c_int | e << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (e >> 11 as libc::c_int | e << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (e >> 25 as libc::c_int | e << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(e & f ^ !e & g)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[(j & 0xf as libc::c_int) as usize]);
        d = (d as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        h = T1
            .wrapping_add(
                (a >> 2 as libc::c_int | a << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (a >> 13 as libc::c_int | a << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (a >> 22 as libc::c_int | a << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(a & b ^ a & c ^ b & c);
        j += 1;
        j;
        s0 = W256[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 7 as libc::c_int | s0 << 32 as libc::c_int - 7 as libc::c_int)
            ^ (s0 >> 18 as libc::c_int | s0 << 32 as libc::c_int - 18 as libc::c_int)
            ^ s0 >> 3 as libc::c_int;
        s1 = W256[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 17 as libc::c_int | s1 << 32 as libc::c_int - 17 as libc::c_int)
            ^ (s1 >> 19 as libc::c_int | s1 << 32 as libc::c_int - 19 as libc::c_int)
            ^ s1 >> 10 as libc::c_int;
        W256[(j & 0xf as libc::c_int) as usize] =
            (W256[(j & 0xf as libc::c_int) as usize] as libc::c_uint).wrapping_add(
                s1.wrapping_add(W256[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int32_t as u_int32_t;
        T1 = g
            .wrapping_add(
                (d >> 6 as libc::c_int | d << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (d >> 11 as libc::c_int | d << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (d >> 25 as libc::c_int | d << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(d & e ^ !d & f)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[(j & 0xf as libc::c_int) as usize]);
        c = (c as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        g = T1
            .wrapping_add(
                (h >> 2 as libc::c_int | h << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (h >> 13 as libc::c_int | h << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (h >> 22 as libc::c_int | h << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(h & a ^ h & b ^ a & b);
        j += 1;
        j;
        s0 = W256[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 7 as libc::c_int | s0 << 32 as libc::c_int - 7 as libc::c_int)
            ^ (s0 >> 18 as libc::c_int | s0 << 32 as libc::c_int - 18 as libc::c_int)
            ^ s0 >> 3 as libc::c_int;
        s1 = W256[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 17 as libc::c_int | s1 << 32 as libc::c_int - 17 as libc::c_int)
            ^ (s1 >> 19 as libc::c_int | s1 << 32 as libc::c_int - 19 as libc::c_int)
            ^ s1 >> 10 as libc::c_int;
        W256[(j & 0xf as libc::c_int) as usize] =
            (W256[(j & 0xf as libc::c_int) as usize] as libc::c_uint).wrapping_add(
                s1.wrapping_add(W256[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int32_t as u_int32_t;
        T1 = f
            .wrapping_add(
                (c >> 6 as libc::c_int | c << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (c >> 11 as libc::c_int | c << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (c >> 25 as libc::c_int | c << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(c & d ^ !c & e)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[(j & 0xf as libc::c_int) as usize]);
        b = (b as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        f = T1
            .wrapping_add(
                (g >> 2 as libc::c_int | g << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (g >> 13 as libc::c_int | g << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (g >> 22 as libc::c_int | g << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(g & h ^ g & a ^ h & a);
        j += 1;
        j;
        s0 = W256[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 7 as libc::c_int | s0 << 32 as libc::c_int - 7 as libc::c_int)
            ^ (s0 >> 18 as libc::c_int | s0 << 32 as libc::c_int - 18 as libc::c_int)
            ^ s0 >> 3 as libc::c_int;
        s1 = W256[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 17 as libc::c_int | s1 << 32 as libc::c_int - 17 as libc::c_int)
            ^ (s1 >> 19 as libc::c_int | s1 << 32 as libc::c_int - 19 as libc::c_int)
            ^ s1 >> 10 as libc::c_int;
        W256[(j & 0xf as libc::c_int) as usize] =
            (W256[(j & 0xf as libc::c_int) as usize] as libc::c_uint).wrapping_add(
                s1.wrapping_add(W256[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int32_t as u_int32_t;
        T1 = e
            .wrapping_add(
                (b >> 6 as libc::c_int | b << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (b >> 11 as libc::c_int | b << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (b >> 25 as libc::c_int | b << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(b & c ^ !b & d)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[(j & 0xf as libc::c_int) as usize]);
        a = (a as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        e = T1
            .wrapping_add(
                (f >> 2 as libc::c_int | f << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (f >> 13 as libc::c_int | f << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (f >> 22 as libc::c_int | f << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(f & g ^ f & h ^ g & h);
        j += 1;
        j;
        s0 = W256[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 7 as libc::c_int | s0 << 32 as libc::c_int - 7 as libc::c_int)
            ^ (s0 >> 18 as libc::c_int | s0 << 32 as libc::c_int - 18 as libc::c_int)
            ^ s0 >> 3 as libc::c_int;
        s1 = W256[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 17 as libc::c_int | s1 << 32 as libc::c_int - 17 as libc::c_int)
            ^ (s1 >> 19 as libc::c_int | s1 << 32 as libc::c_int - 19 as libc::c_int)
            ^ s1 >> 10 as libc::c_int;
        W256[(j & 0xf as libc::c_int) as usize] =
            (W256[(j & 0xf as libc::c_int) as usize] as libc::c_uint).wrapping_add(
                s1.wrapping_add(W256[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int32_t as u_int32_t;
        T1 = d
            .wrapping_add(
                (a >> 6 as libc::c_int | a << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (a >> 11 as libc::c_int | a << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (a >> 25 as libc::c_int | a << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(a & b ^ !a & c)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[(j & 0xf as libc::c_int) as usize]);
        h = (h as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        d = T1
            .wrapping_add(
                (e >> 2 as libc::c_int | e << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (e >> 13 as libc::c_int | e << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (e >> 22 as libc::c_int | e << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(e & f ^ e & g ^ f & g);
        j += 1;
        j;
        s0 = W256[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 7 as libc::c_int | s0 << 32 as libc::c_int - 7 as libc::c_int)
            ^ (s0 >> 18 as libc::c_int | s0 << 32 as libc::c_int - 18 as libc::c_int)
            ^ s0 >> 3 as libc::c_int;
        s1 = W256[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 17 as libc::c_int | s1 << 32 as libc::c_int - 17 as libc::c_int)
            ^ (s1 >> 19 as libc::c_int | s1 << 32 as libc::c_int - 19 as libc::c_int)
            ^ s1 >> 10 as libc::c_int;
        W256[(j & 0xf as libc::c_int) as usize] =
            (W256[(j & 0xf as libc::c_int) as usize] as libc::c_uint).wrapping_add(
                s1.wrapping_add(W256[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int32_t as u_int32_t;
        T1 = c
            .wrapping_add(
                (h >> 6 as libc::c_int | h << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (h >> 11 as libc::c_int | h << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (h >> 25 as libc::c_int | h << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(h & a ^ !h & b)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[(j & 0xf as libc::c_int) as usize]);
        g = (g as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        c = T1
            .wrapping_add(
                (d >> 2 as libc::c_int | d << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (d >> 13 as libc::c_int | d << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (d >> 22 as libc::c_int | d << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(d & e ^ d & f ^ e & f);
        j += 1;
        j;
        s0 = W256[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 7 as libc::c_int | s0 << 32 as libc::c_int - 7 as libc::c_int)
            ^ (s0 >> 18 as libc::c_int | s0 << 32 as libc::c_int - 18 as libc::c_int)
            ^ s0 >> 3 as libc::c_int;
        s1 = W256[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 17 as libc::c_int | s1 << 32 as libc::c_int - 17 as libc::c_int)
            ^ (s1 >> 19 as libc::c_int | s1 << 32 as libc::c_int - 19 as libc::c_int)
            ^ s1 >> 10 as libc::c_int;
        W256[(j & 0xf as libc::c_int) as usize] =
            (W256[(j & 0xf as libc::c_int) as usize] as libc::c_uint).wrapping_add(
                s1.wrapping_add(W256[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int32_t as u_int32_t;
        T1 = b
            .wrapping_add(
                (g >> 6 as libc::c_int | g << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (g >> 11 as libc::c_int | g << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (g >> 25 as libc::c_int | g << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(g & h ^ !g & a)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[(j & 0xf as libc::c_int) as usize]);
        f = (f as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        b = T1
            .wrapping_add(
                (c >> 2 as libc::c_int | c << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (c >> 13 as libc::c_int | c << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (c >> 22 as libc::c_int | c << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(c & d ^ c & e ^ d & e);
        j += 1;
        j;
        s0 = W256[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 7 as libc::c_int | s0 << 32 as libc::c_int - 7 as libc::c_int)
            ^ (s0 >> 18 as libc::c_int | s0 << 32 as libc::c_int - 18 as libc::c_int)
            ^ s0 >> 3 as libc::c_int;
        s1 = W256[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 17 as libc::c_int | s1 << 32 as libc::c_int - 17 as libc::c_int)
            ^ (s1 >> 19 as libc::c_int | s1 << 32 as libc::c_int - 19 as libc::c_int)
            ^ s1 >> 10 as libc::c_int;
        W256[(j & 0xf as libc::c_int) as usize] =
            (W256[(j & 0xf as libc::c_int) as usize] as libc::c_uint).wrapping_add(
                s1.wrapping_add(W256[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int32_t as u_int32_t;
        T1 = a
            .wrapping_add(
                (f >> 6 as libc::c_int | f << 32 as libc::c_int - 6 as libc::c_int)
                    ^ (f >> 11 as libc::c_int | f << 32 as libc::c_int - 11 as libc::c_int)
                    ^ (f >> 25 as libc::c_int | f << 32 as libc::c_int - 25 as libc::c_int),
            )
            .wrapping_add(f & g ^ !f & h)
            .wrapping_add(K256[j as usize])
            .wrapping_add(W256[(j & 0xf as libc::c_int) as usize]);
        e = (e as libc::c_uint).wrapping_add(T1) as u_int32_t as u_int32_t;
        a = T1
            .wrapping_add(
                (b >> 2 as libc::c_int | b << 32 as libc::c_int - 2 as libc::c_int)
                    ^ (b >> 13 as libc::c_int | b << 32 as libc::c_int - 13 as libc::c_int)
                    ^ (b >> 22 as libc::c_int | b << 32 as libc::c_int - 22 as libc::c_int),
            )
            .wrapping_add(b & c ^ b & d ^ c & d);
        j += 1;
        j;
        if !(j < 64 as libc::c_int) {
            break;
        }
    }
    let ref mut fresh0 = *state.offset(0 as libc::c_int as isize);
    *fresh0 = (*fresh0 as libc::c_uint).wrapping_add(a) as u_int32_t as u_int32_t;
    let ref mut fresh1 = *state.offset(1 as libc::c_int as isize);
    *fresh1 = (*fresh1 as libc::c_uint).wrapping_add(b) as u_int32_t as u_int32_t;
    let ref mut fresh2 = *state.offset(2 as libc::c_int as isize);
    *fresh2 = (*fresh2 as libc::c_uint).wrapping_add(c) as u_int32_t as u_int32_t;
    let ref mut fresh3 = *state.offset(3 as libc::c_int as isize);
    *fresh3 = (*fresh3 as libc::c_uint).wrapping_add(d) as u_int32_t as u_int32_t;
    let ref mut fresh4 = *state.offset(4 as libc::c_int as isize);
    *fresh4 = (*fresh4 as libc::c_uint).wrapping_add(e) as u_int32_t as u_int32_t;
    let ref mut fresh5 = *state.offset(5 as libc::c_int as isize);
    *fresh5 = (*fresh5 as libc::c_uint).wrapping_add(f) as u_int32_t as u_int32_t;
    let ref mut fresh6 = *state.offset(6 as libc::c_int as isize);
    *fresh6 = (*fresh6 as libc::c_uint).wrapping_add(g) as u_int32_t as u_int32_t;
    let ref mut fresh7 = *state.offset(7 as libc::c_int as isize);
    *fresh7 = (*fresh7 as libc::c_uint).wrapping_add(h) as u_int32_t as u_int32_t;
    T1 = 0 as libc::c_int as u_int32_t;
    h = T1;
    g = h;
    f = g;
    e = f;
    d = e;
    c = d;
    b = c;
    a = b;
}
#[no_mangle]
pub unsafe extern "C" fn SHA256Update(
    mut context: *mut SHA2_CTX,
    mut data: *const u_int8_t,
    mut len: size_t,
) {
    let mut freespace: u_int64_t = 0;
    let mut usedspace: u_int64_t = 0;
    if len == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    usedspace = ((*context).bitcount[0 as libc::c_int as usize] >> 3 as libc::c_int)
        .wrapping_rem(64 as libc::c_int as libc::c_ulong);
    if usedspace > 0 as libc::c_int as libc::c_ulong {
        freespace = (64 as libc::c_int as libc::c_ulong).wrapping_sub(usedspace);
        if len >= freespace {
            memcpy(
                &mut *((*context).buffer).as_mut_ptr().offset(usedspace as isize) as *mut u_int8_t
                    as *mut libc::c_void,
                data as *const libc::c_void,
                freespace,
            );
            (*context).bitcount[0 as libc::c_int as usize] =
                ((*context).bitcount[0 as libc::c_int as usize] as libc::c_ulong)
                    .wrapping_add(freespace << 3 as libc::c_int) as u_int64_t
                    as u_int64_t;
            len = (len as libc::c_ulong).wrapping_sub(freespace) as size_t as size_t;
            data = data.offset(freespace as isize);
            SHA256Transform(
                ((*context).state.st32).as_mut_ptr(),
                ((*context).buffer).as_mut_ptr() as *const u_int8_t,
            );
        } else {
            memcpy(
                &mut *((*context).buffer).as_mut_ptr().offset(usedspace as isize) as *mut u_int8_t
                    as *mut libc::c_void,
                data as *const libc::c_void,
                len,
            );
            (*context).bitcount[0 as libc::c_int as usize] =
                ((*context).bitcount[0 as libc::c_int as usize] as libc::c_ulong)
                    .wrapping_add(len << 3 as libc::c_int) as u_int64_t
                    as u_int64_t;
            freespace = 0 as libc::c_int as u_int64_t;
            usedspace = freespace;
            return;
        }
    }
    while len >= 64 as libc::c_int as libc::c_ulong {
        SHA256Transform(((*context).state.st32).as_mut_ptr(), data);
        (*context).bitcount[0 as libc::c_int as usize] =
            ((*context).bitcount[0 as libc::c_int as usize] as libc::c_ulong)
                .wrapping_add(((64 as libc::c_int) << 3 as libc::c_int) as libc::c_ulong)
                as u_int64_t as u_int64_t;
        len = (len as libc::c_ulong).wrapping_sub(64 as libc::c_int as libc::c_ulong) as size_t
            as size_t;
        data = data.offset(64 as libc::c_int as isize);
    }
    if len > 0 as libc::c_int as libc::c_ulong {
        memcpy(
            ((*context).buffer).as_mut_ptr() as *mut libc::c_void,
            data as *const libc::c_void,
            len,
        );
        (*context).bitcount[0 as libc::c_int as usize] =
            ((*context).bitcount[0 as libc::c_int as usize] as libc::c_ulong)
                .wrapping_add(len << 3 as libc::c_int) as u_int64_t as u_int64_t;
    }
    freespace = 0 as libc::c_int as u_int64_t;
    usedspace = freespace;
}
#[no_mangle]
pub unsafe extern "C" fn SHA256Pad(mut context: *mut SHA2_CTX) {
    let mut usedspace: libc::c_uint = 0;
    usedspace = ((*context).bitcount[0 as libc::c_int as usize] >> 3 as libc::c_int)
        .wrapping_rem(64 as libc::c_int as libc::c_ulong) as libc::c_uint;
    if usedspace > 0 as libc::c_int as libc::c_uint {
        let fresh8 = usedspace;
        usedspace = usedspace.wrapping_add(1);
        (*context).buffer[fresh8 as usize] = 0x80 as libc::c_int as u_int8_t;
        if usedspace <= (64 as libc::c_int - 8 as libc::c_int) as libc::c_uint {
            memset(
                &mut *((*context).buffer).as_mut_ptr().offset(usedspace as isize) as *mut u_int8_t
                    as *mut libc::c_void,
                0 as libc::c_int,
                ((64 as libc::c_int - 8 as libc::c_int) as libc::c_uint).wrapping_sub(usedspace)
                    as size_t,
            );
        } else {
            if usedspace < 64 as libc::c_int as libc::c_uint {
                memset(
                    &mut *((*context).buffer).as_mut_ptr().offset(usedspace as isize)
                        as *mut u_int8_t as *mut libc::c_void,
                    0 as libc::c_int,
                    (64 as libc::c_int as libc::c_uint).wrapping_sub(usedspace) as size_t,
                );
            }
            SHA256Transform(
                ((*context).state.st32).as_mut_ptr(),
                ((*context).buffer).as_mut_ptr() as *const u_int8_t,
            );
            memset(
                ((*context).buffer).as_mut_ptr() as *mut libc::c_void,
                0 as libc::c_int,
                (64 as libc::c_int - 8 as libc::c_int) as size_t,
            );
        }
    } else {
        memset(
            ((*context).buffer).as_mut_ptr() as *mut libc::c_void,
            0 as libc::c_int,
            (64 as libc::c_int - 8 as libc::c_int) as size_t,
        );
        *((*context).buffer).as_mut_ptr() = 0x80 as libc::c_int as u_int8_t;
    }
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((64 as libc::c_int - 8 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(0 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 56 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((64 as libc::c_int - 8 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(1 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 48 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((64 as libc::c_int - 8 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(2 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 40 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((64 as libc::c_int - 8 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(3 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 32 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((64 as libc::c_int - 8 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(4 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 24 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((64 as libc::c_int - 8 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(5 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 16 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((64 as libc::c_int - 8 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(6 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 8 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((64 as libc::c_int - 8 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(7 as libc::c_int as isize) =
        (*context).bitcount[0 as libc::c_int as usize] as u_int8_t;
    SHA256Transform(
        ((*context).state.st32).as_mut_ptr(),
        ((*context).buffer).as_mut_ptr() as *const u_int8_t,
    );
    usedspace = 0 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn SHA256Final(mut digest: *mut u_int8_t, mut context: *mut SHA2_CTX) {
    SHA256Pad(context);
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 8 as libc::c_int {
        *digest
            .offset((i * 4 as libc::c_int) as isize)
            .offset(0 as libc::c_int as isize) =
            ((*context).state.st32[i as usize] >> 24 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 4 as libc::c_int) as isize)
            .offset(1 as libc::c_int as isize) =
            ((*context).state.st32[i as usize] >> 16 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 4 as libc::c_int) as isize)
            .offset(2 as libc::c_int as isize) =
            ((*context).state.st32[i as usize] >> 8 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 4 as libc::c_int) as isize)
            .offset(3 as libc::c_int as isize) = (*context).state.st32[i as usize] as u_int8_t;
        i += 1;
        i;
    }
    explicit_bzero(
        context as *mut libc::c_void,
        ::core::mem::size_of::<SHA2_CTX>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn SHA512Init(mut context: *mut SHA2_CTX) {
    memcpy(
        ((*context).state.st64).as_mut_ptr() as *mut libc::c_void,
        sha512_initial_hash_value.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[u_int64_t; 8]>() as libc::c_ulong,
    );
    memset(
        ((*context).buffer).as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[u_int8_t; 128]>() as libc::c_ulong,
    );
    (*context).bitcount[1 as libc::c_int as usize] = 0 as libc::c_int as u_int64_t;
    (*context).bitcount[0 as libc::c_int as usize] = (*context).bitcount[1 as libc::c_int as usize];
}
#[no_mangle]
pub unsafe extern "C" fn SHA512Transform(mut state: *mut u_int64_t, mut data: *const u_int8_t) {
    let mut a: u_int64_t = 0;
    let mut b: u_int64_t = 0;
    let mut c: u_int64_t = 0;
    let mut d: u_int64_t = 0;
    let mut e: u_int64_t = 0;
    let mut f: u_int64_t = 0;
    let mut g: u_int64_t = 0;
    let mut h: u_int64_t = 0;
    let mut s0: u_int64_t = 0;
    let mut s1: u_int64_t = 0;
    let mut T1: u_int64_t = 0;
    let mut W512: [u_int64_t; 16] = [0; 16];
    let mut j: libc::c_int = 0;
    a = *state.offset(0 as libc::c_int as isize);
    b = *state.offset(1 as libc::c_int as isize);
    c = *state.offset(2 as libc::c_int as isize);
    d = *state.offset(3 as libc::c_int as isize);
    e = *state.offset(4 as libc::c_int as isize);
    f = *state.offset(5 as libc::c_int as isize);
    g = *state.offset(6 as libc::c_int as isize);
    h = *state.offset(7 as libc::c_int as isize);
    j = 0 as libc::c_int;
    loop {
        W512[j as usize] = *data.offset(7 as libc::c_int as isize) as u_int64_t
            | (*data.offset(6 as libc::c_int as isize) as u_int64_t) << 8 as libc::c_int
            | (*data.offset(5 as libc::c_int as isize) as u_int64_t) << 16 as libc::c_int
            | (*data.offset(4 as libc::c_int as isize) as u_int64_t) << 24 as libc::c_int
            | (*data.offset(3 as libc::c_int as isize) as u_int64_t) << 32 as libc::c_int
            | (*data.offset(2 as libc::c_int as isize) as u_int64_t) << 40 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int64_t) << 48 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int64_t) << 56 as libc::c_int;
        data = data.offset(8 as libc::c_int as isize);
        T1 = h
            .wrapping_add(
                (e >> 14 as libc::c_int | e << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (e >> 18 as libc::c_int | e << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (e >> 41 as libc::c_int | e << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(e & f ^ !e & g)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[j as usize]);
        d = (d as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        h = T1
            .wrapping_add(
                (a >> 28 as libc::c_int | a << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (a >> 34 as libc::c_int | a << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (a >> 39 as libc::c_int | a << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(a & b ^ a & c ^ b & c);
        j += 1;
        j;
        W512[j as usize] = *data.offset(7 as libc::c_int as isize) as u_int64_t
            | (*data.offset(6 as libc::c_int as isize) as u_int64_t) << 8 as libc::c_int
            | (*data.offset(5 as libc::c_int as isize) as u_int64_t) << 16 as libc::c_int
            | (*data.offset(4 as libc::c_int as isize) as u_int64_t) << 24 as libc::c_int
            | (*data.offset(3 as libc::c_int as isize) as u_int64_t) << 32 as libc::c_int
            | (*data.offset(2 as libc::c_int as isize) as u_int64_t) << 40 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int64_t) << 48 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int64_t) << 56 as libc::c_int;
        data = data.offset(8 as libc::c_int as isize);
        T1 = g
            .wrapping_add(
                (d >> 14 as libc::c_int | d << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (d >> 18 as libc::c_int | d << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (d >> 41 as libc::c_int | d << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(d & e ^ !d & f)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[j as usize]);
        c = (c as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        g = T1
            .wrapping_add(
                (h >> 28 as libc::c_int | h << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (h >> 34 as libc::c_int | h << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (h >> 39 as libc::c_int | h << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(h & a ^ h & b ^ a & b);
        j += 1;
        j;
        W512[j as usize] = *data.offset(7 as libc::c_int as isize) as u_int64_t
            | (*data.offset(6 as libc::c_int as isize) as u_int64_t) << 8 as libc::c_int
            | (*data.offset(5 as libc::c_int as isize) as u_int64_t) << 16 as libc::c_int
            | (*data.offset(4 as libc::c_int as isize) as u_int64_t) << 24 as libc::c_int
            | (*data.offset(3 as libc::c_int as isize) as u_int64_t) << 32 as libc::c_int
            | (*data.offset(2 as libc::c_int as isize) as u_int64_t) << 40 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int64_t) << 48 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int64_t) << 56 as libc::c_int;
        data = data.offset(8 as libc::c_int as isize);
        T1 = f
            .wrapping_add(
                (c >> 14 as libc::c_int | c << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (c >> 18 as libc::c_int | c << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (c >> 41 as libc::c_int | c << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(c & d ^ !c & e)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[j as usize]);
        b = (b as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        f = T1
            .wrapping_add(
                (g >> 28 as libc::c_int | g << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (g >> 34 as libc::c_int | g << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (g >> 39 as libc::c_int | g << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(g & h ^ g & a ^ h & a);
        j += 1;
        j;
        W512[j as usize] = *data.offset(7 as libc::c_int as isize) as u_int64_t
            | (*data.offset(6 as libc::c_int as isize) as u_int64_t) << 8 as libc::c_int
            | (*data.offset(5 as libc::c_int as isize) as u_int64_t) << 16 as libc::c_int
            | (*data.offset(4 as libc::c_int as isize) as u_int64_t) << 24 as libc::c_int
            | (*data.offset(3 as libc::c_int as isize) as u_int64_t) << 32 as libc::c_int
            | (*data.offset(2 as libc::c_int as isize) as u_int64_t) << 40 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int64_t) << 48 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int64_t) << 56 as libc::c_int;
        data = data.offset(8 as libc::c_int as isize);
        T1 = e
            .wrapping_add(
                (b >> 14 as libc::c_int | b << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (b >> 18 as libc::c_int | b << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (b >> 41 as libc::c_int | b << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(b & c ^ !b & d)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[j as usize]);
        a = (a as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        e = T1
            .wrapping_add(
                (f >> 28 as libc::c_int | f << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (f >> 34 as libc::c_int | f << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (f >> 39 as libc::c_int | f << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(f & g ^ f & h ^ g & h);
        j += 1;
        j;
        W512[j as usize] = *data.offset(7 as libc::c_int as isize) as u_int64_t
            | (*data.offset(6 as libc::c_int as isize) as u_int64_t) << 8 as libc::c_int
            | (*data.offset(5 as libc::c_int as isize) as u_int64_t) << 16 as libc::c_int
            | (*data.offset(4 as libc::c_int as isize) as u_int64_t) << 24 as libc::c_int
            | (*data.offset(3 as libc::c_int as isize) as u_int64_t) << 32 as libc::c_int
            | (*data.offset(2 as libc::c_int as isize) as u_int64_t) << 40 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int64_t) << 48 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int64_t) << 56 as libc::c_int;
        data = data.offset(8 as libc::c_int as isize);
        T1 = d
            .wrapping_add(
                (a >> 14 as libc::c_int | a << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (a >> 18 as libc::c_int | a << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (a >> 41 as libc::c_int | a << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(a & b ^ !a & c)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[j as usize]);
        h = (h as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        d = T1
            .wrapping_add(
                (e >> 28 as libc::c_int | e << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (e >> 34 as libc::c_int | e << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (e >> 39 as libc::c_int | e << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(e & f ^ e & g ^ f & g);
        j += 1;
        j;
        W512[j as usize] = *data.offset(7 as libc::c_int as isize) as u_int64_t
            | (*data.offset(6 as libc::c_int as isize) as u_int64_t) << 8 as libc::c_int
            | (*data.offset(5 as libc::c_int as isize) as u_int64_t) << 16 as libc::c_int
            | (*data.offset(4 as libc::c_int as isize) as u_int64_t) << 24 as libc::c_int
            | (*data.offset(3 as libc::c_int as isize) as u_int64_t) << 32 as libc::c_int
            | (*data.offset(2 as libc::c_int as isize) as u_int64_t) << 40 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int64_t) << 48 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int64_t) << 56 as libc::c_int;
        data = data.offset(8 as libc::c_int as isize);
        T1 = c
            .wrapping_add(
                (h >> 14 as libc::c_int | h << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (h >> 18 as libc::c_int | h << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (h >> 41 as libc::c_int | h << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(h & a ^ !h & b)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[j as usize]);
        g = (g as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        c = T1
            .wrapping_add(
                (d >> 28 as libc::c_int | d << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (d >> 34 as libc::c_int | d << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (d >> 39 as libc::c_int | d << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(d & e ^ d & f ^ e & f);
        j += 1;
        j;
        W512[j as usize] = *data.offset(7 as libc::c_int as isize) as u_int64_t
            | (*data.offset(6 as libc::c_int as isize) as u_int64_t) << 8 as libc::c_int
            | (*data.offset(5 as libc::c_int as isize) as u_int64_t) << 16 as libc::c_int
            | (*data.offset(4 as libc::c_int as isize) as u_int64_t) << 24 as libc::c_int
            | (*data.offset(3 as libc::c_int as isize) as u_int64_t) << 32 as libc::c_int
            | (*data.offset(2 as libc::c_int as isize) as u_int64_t) << 40 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int64_t) << 48 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int64_t) << 56 as libc::c_int;
        data = data.offset(8 as libc::c_int as isize);
        T1 = b
            .wrapping_add(
                (g >> 14 as libc::c_int | g << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (g >> 18 as libc::c_int | g << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (g >> 41 as libc::c_int | g << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(g & h ^ !g & a)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[j as usize]);
        f = (f as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        b = T1
            .wrapping_add(
                (c >> 28 as libc::c_int | c << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (c >> 34 as libc::c_int | c << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (c >> 39 as libc::c_int | c << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(c & d ^ c & e ^ d & e);
        j += 1;
        j;
        W512[j as usize] = *data.offset(7 as libc::c_int as isize) as u_int64_t
            | (*data.offset(6 as libc::c_int as isize) as u_int64_t) << 8 as libc::c_int
            | (*data.offset(5 as libc::c_int as isize) as u_int64_t) << 16 as libc::c_int
            | (*data.offset(4 as libc::c_int as isize) as u_int64_t) << 24 as libc::c_int
            | (*data.offset(3 as libc::c_int as isize) as u_int64_t) << 32 as libc::c_int
            | (*data.offset(2 as libc::c_int as isize) as u_int64_t) << 40 as libc::c_int
            | (*data.offset(1 as libc::c_int as isize) as u_int64_t) << 48 as libc::c_int
            | (*data.offset(0 as libc::c_int as isize) as u_int64_t) << 56 as libc::c_int;
        data = data.offset(8 as libc::c_int as isize);
        T1 = a
            .wrapping_add(
                (f >> 14 as libc::c_int | f << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (f >> 18 as libc::c_int | f << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (f >> 41 as libc::c_int | f << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(f & g ^ !f & h)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[j as usize]);
        e = (e as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        a = T1
            .wrapping_add(
                (b >> 28 as libc::c_int | b << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (b >> 34 as libc::c_int | b << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (b >> 39 as libc::c_int | b << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(b & c ^ b & d ^ c & d);
        j += 1;
        j;
        if !(j < 16 as libc::c_int) {
            break;
        }
    }
    loop {
        s0 = W512[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 1 as libc::c_int | s0 << 64 as libc::c_int - 1 as libc::c_int)
            ^ (s0 >> 8 as libc::c_int | s0 << 64 as libc::c_int - 8 as libc::c_int)
            ^ s0 >> 7 as libc::c_int;
        s1 = W512[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 19 as libc::c_int | s1 << 64 as libc::c_int - 19 as libc::c_int)
            ^ (s1 >> 61 as libc::c_int | s1 << 64 as libc::c_int - 61 as libc::c_int)
            ^ s1 >> 6 as libc::c_int;
        W512[(j & 0xf as libc::c_int) as usize] =
            (W512[(j & 0xf as libc::c_int) as usize] as libc::c_ulong).wrapping_add(
                s1.wrapping_add(W512[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int64_t as u_int64_t;
        T1 = h
            .wrapping_add(
                (e >> 14 as libc::c_int | e << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (e >> 18 as libc::c_int | e << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (e >> 41 as libc::c_int | e << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(e & f ^ !e & g)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[(j & 0xf as libc::c_int) as usize]);
        d = (d as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        h = T1
            .wrapping_add(
                (a >> 28 as libc::c_int | a << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (a >> 34 as libc::c_int | a << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (a >> 39 as libc::c_int | a << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(a & b ^ a & c ^ b & c);
        j += 1;
        j;
        s0 = W512[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 1 as libc::c_int | s0 << 64 as libc::c_int - 1 as libc::c_int)
            ^ (s0 >> 8 as libc::c_int | s0 << 64 as libc::c_int - 8 as libc::c_int)
            ^ s0 >> 7 as libc::c_int;
        s1 = W512[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 19 as libc::c_int | s1 << 64 as libc::c_int - 19 as libc::c_int)
            ^ (s1 >> 61 as libc::c_int | s1 << 64 as libc::c_int - 61 as libc::c_int)
            ^ s1 >> 6 as libc::c_int;
        W512[(j & 0xf as libc::c_int) as usize] =
            (W512[(j & 0xf as libc::c_int) as usize] as libc::c_ulong).wrapping_add(
                s1.wrapping_add(W512[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int64_t as u_int64_t;
        T1 = g
            .wrapping_add(
                (d >> 14 as libc::c_int | d << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (d >> 18 as libc::c_int | d << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (d >> 41 as libc::c_int | d << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(d & e ^ !d & f)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[(j & 0xf as libc::c_int) as usize]);
        c = (c as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        g = T1
            .wrapping_add(
                (h >> 28 as libc::c_int | h << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (h >> 34 as libc::c_int | h << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (h >> 39 as libc::c_int | h << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(h & a ^ h & b ^ a & b);
        j += 1;
        j;
        s0 = W512[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 1 as libc::c_int | s0 << 64 as libc::c_int - 1 as libc::c_int)
            ^ (s0 >> 8 as libc::c_int | s0 << 64 as libc::c_int - 8 as libc::c_int)
            ^ s0 >> 7 as libc::c_int;
        s1 = W512[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 19 as libc::c_int | s1 << 64 as libc::c_int - 19 as libc::c_int)
            ^ (s1 >> 61 as libc::c_int | s1 << 64 as libc::c_int - 61 as libc::c_int)
            ^ s1 >> 6 as libc::c_int;
        W512[(j & 0xf as libc::c_int) as usize] =
            (W512[(j & 0xf as libc::c_int) as usize] as libc::c_ulong).wrapping_add(
                s1.wrapping_add(W512[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int64_t as u_int64_t;
        T1 = f
            .wrapping_add(
                (c >> 14 as libc::c_int | c << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (c >> 18 as libc::c_int | c << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (c >> 41 as libc::c_int | c << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(c & d ^ !c & e)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[(j & 0xf as libc::c_int) as usize]);
        b = (b as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        f = T1
            .wrapping_add(
                (g >> 28 as libc::c_int | g << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (g >> 34 as libc::c_int | g << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (g >> 39 as libc::c_int | g << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(g & h ^ g & a ^ h & a);
        j += 1;
        j;
        s0 = W512[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 1 as libc::c_int | s0 << 64 as libc::c_int - 1 as libc::c_int)
            ^ (s0 >> 8 as libc::c_int | s0 << 64 as libc::c_int - 8 as libc::c_int)
            ^ s0 >> 7 as libc::c_int;
        s1 = W512[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 19 as libc::c_int | s1 << 64 as libc::c_int - 19 as libc::c_int)
            ^ (s1 >> 61 as libc::c_int | s1 << 64 as libc::c_int - 61 as libc::c_int)
            ^ s1 >> 6 as libc::c_int;
        W512[(j & 0xf as libc::c_int) as usize] =
            (W512[(j & 0xf as libc::c_int) as usize] as libc::c_ulong).wrapping_add(
                s1.wrapping_add(W512[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int64_t as u_int64_t;
        T1 = e
            .wrapping_add(
                (b >> 14 as libc::c_int | b << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (b >> 18 as libc::c_int | b << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (b >> 41 as libc::c_int | b << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(b & c ^ !b & d)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[(j & 0xf as libc::c_int) as usize]);
        a = (a as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        e = T1
            .wrapping_add(
                (f >> 28 as libc::c_int | f << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (f >> 34 as libc::c_int | f << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (f >> 39 as libc::c_int | f << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(f & g ^ f & h ^ g & h);
        j += 1;
        j;
        s0 = W512[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 1 as libc::c_int | s0 << 64 as libc::c_int - 1 as libc::c_int)
            ^ (s0 >> 8 as libc::c_int | s0 << 64 as libc::c_int - 8 as libc::c_int)
            ^ s0 >> 7 as libc::c_int;
        s1 = W512[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 19 as libc::c_int | s1 << 64 as libc::c_int - 19 as libc::c_int)
            ^ (s1 >> 61 as libc::c_int | s1 << 64 as libc::c_int - 61 as libc::c_int)
            ^ s1 >> 6 as libc::c_int;
        W512[(j & 0xf as libc::c_int) as usize] =
            (W512[(j & 0xf as libc::c_int) as usize] as libc::c_ulong).wrapping_add(
                s1.wrapping_add(W512[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int64_t as u_int64_t;
        T1 = d
            .wrapping_add(
                (a >> 14 as libc::c_int | a << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (a >> 18 as libc::c_int | a << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (a >> 41 as libc::c_int | a << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(a & b ^ !a & c)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[(j & 0xf as libc::c_int) as usize]);
        h = (h as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        d = T1
            .wrapping_add(
                (e >> 28 as libc::c_int | e << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (e >> 34 as libc::c_int | e << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (e >> 39 as libc::c_int | e << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(e & f ^ e & g ^ f & g);
        j += 1;
        j;
        s0 = W512[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 1 as libc::c_int | s0 << 64 as libc::c_int - 1 as libc::c_int)
            ^ (s0 >> 8 as libc::c_int | s0 << 64 as libc::c_int - 8 as libc::c_int)
            ^ s0 >> 7 as libc::c_int;
        s1 = W512[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 19 as libc::c_int | s1 << 64 as libc::c_int - 19 as libc::c_int)
            ^ (s1 >> 61 as libc::c_int | s1 << 64 as libc::c_int - 61 as libc::c_int)
            ^ s1 >> 6 as libc::c_int;
        W512[(j & 0xf as libc::c_int) as usize] =
            (W512[(j & 0xf as libc::c_int) as usize] as libc::c_ulong).wrapping_add(
                s1.wrapping_add(W512[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int64_t as u_int64_t;
        T1 = c
            .wrapping_add(
                (h >> 14 as libc::c_int | h << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (h >> 18 as libc::c_int | h << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (h >> 41 as libc::c_int | h << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(h & a ^ !h & b)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[(j & 0xf as libc::c_int) as usize]);
        g = (g as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        c = T1
            .wrapping_add(
                (d >> 28 as libc::c_int | d << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (d >> 34 as libc::c_int | d << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (d >> 39 as libc::c_int | d << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(d & e ^ d & f ^ e & f);
        j += 1;
        j;
        s0 = W512[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 1 as libc::c_int | s0 << 64 as libc::c_int - 1 as libc::c_int)
            ^ (s0 >> 8 as libc::c_int | s0 << 64 as libc::c_int - 8 as libc::c_int)
            ^ s0 >> 7 as libc::c_int;
        s1 = W512[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 19 as libc::c_int | s1 << 64 as libc::c_int - 19 as libc::c_int)
            ^ (s1 >> 61 as libc::c_int | s1 << 64 as libc::c_int - 61 as libc::c_int)
            ^ s1 >> 6 as libc::c_int;
        W512[(j & 0xf as libc::c_int) as usize] =
            (W512[(j & 0xf as libc::c_int) as usize] as libc::c_ulong).wrapping_add(
                s1.wrapping_add(W512[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int64_t as u_int64_t;
        T1 = b
            .wrapping_add(
                (g >> 14 as libc::c_int | g << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (g >> 18 as libc::c_int | g << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (g >> 41 as libc::c_int | g << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(g & h ^ !g & a)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[(j & 0xf as libc::c_int) as usize]);
        f = (f as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        b = T1
            .wrapping_add(
                (c >> 28 as libc::c_int | c << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (c >> 34 as libc::c_int | c << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (c >> 39 as libc::c_int | c << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(c & d ^ c & e ^ d & e);
        j += 1;
        j;
        s0 = W512[(j + 1 as libc::c_int & 0xf as libc::c_int) as usize];
        s0 = (s0 >> 1 as libc::c_int | s0 << 64 as libc::c_int - 1 as libc::c_int)
            ^ (s0 >> 8 as libc::c_int | s0 << 64 as libc::c_int - 8 as libc::c_int)
            ^ s0 >> 7 as libc::c_int;
        s1 = W512[(j + 14 as libc::c_int & 0xf as libc::c_int) as usize];
        s1 = (s1 >> 19 as libc::c_int | s1 << 64 as libc::c_int - 19 as libc::c_int)
            ^ (s1 >> 61 as libc::c_int | s1 << 64 as libc::c_int - 61 as libc::c_int)
            ^ s1 >> 6 as libc::c_int;
        W512[(j & 0xf as libc::c_int) as usize] =
            (W512[(j & 0xf as libc::c_int) as usize] as libc::c_ulong).wrapping_add(
                s1.wrapping_add(W512[(j + 9 as libc::c_int & 0xf as libc::c_int) as usize])
                    .wrapping_add(s0),
            ) as u_int64_t as u_int64_t;
        T1 = a
            .wrapping_add(
                (f >> 14 as libc::c_int | f << 64 as libc::c_int - 14 as libc::c_int)
                    ^ (f >> 18 as libc::c_int | f << 64 as libc::c_int - 18 as libc::c_int)
                    ^ (f >> 41 as libc::c_int | f << 64 as libc::c_int - 41 as libc::c_int),
            )
            .wrapping_add(f & g ^ !f & h)
            .wrapping_add(K512[j as usize])
            .wrapping_add(W512[(j & 0xf as libc::c_int) as usize]);
        e = (e as libc::c_ulong).wrapping_add(T1) as u_int64_t as u_int64_t;
        a = T1
            .wrapping_add(
                (b >> 28 as libc::c_int | b << 64 as libc::c_int - 28 as libc::c_int)
                    ^ (b >> 34 as libc::c_int | b << 64 as libc::c_int - 34 as libc::c_int)
                    ^ (b >> 39 as libc::c_int | b << 64 as libc::c_int - 39 as libc::c_int),
            )
            .wrapping_add(b & c ^ b & d ^ c & d);
        j += 1;
        j;
        if !(j < 80 as libc::c_int) {
            break;
        }
    }
    let ref mut fresh9 = *state.offset(0 as libc::c_int as isize);
    *fresh9 = (*fresh9 as libc::c_ulong).wrapping_add(a) as u_int64_t as u_int64_t;
    let ref mut fresh10 = *state.offset(1 as libc::c_int as isize);
    *fresh10 = (*fresh10 as libc::c_ulong).wrapping_add(b) as u_int64_t as u_int64_t;
    let ref mut fresh11 = *state.offset(2 as libc::c_int as isize);
    *fresh11 = (*fresh11 as libc::c_ulong).wrapping_add(c) as u_int64_t as u_int64_t;
    let ref mut fresh12 = *state.offset(3 as libc::c_int as isize);
    *fresh12 = (*fresh12 as libc::c_ulong).wrapping_add(d) as u_int64_t as u_int64_t;
    let ref mut fresh13 = *state.offset(4 as libc::c_int as isize);
    *fresh13 = (*fresh13 as libc::c_ulong).wrapping_add(e) as u_int64_t as u_int64_t;
    let ref mut fresh14 = *state.offset(5 as libc::c_int as isize);
    *fresh14 = (*fresh14 as libc::c_ulong).wrapping_add(f) as u_int64_t as u_int64_t;
    let ref mut fresh15 = *state.offset(6 as libc::c_int as isize);
    *fresh15 = (*fresh15 as libc::c_ulong).wrapping_add(g) as u_int64_t as u_int64_t;
    let ref mut fresh16 = *state.offset(7 as libc::c_int as isize);
    *fresh16 = (*fresh16 as libc::c_ulong).wrapping_add(h) as u_int64_t as u_int64_t;
    T1 = 0 as libc::c_int as u_int64_t;
    h = T1;
    g = h;
    f = g;
    e = f;
    d = e;
    c = d;
    b = c;
    a = b;
}
#[no_mangle]
pub unsafe extern "C" fn SHA512Update(
    mut context: *mut SHA2_CTX,
    mut data: *const u_int8_t,
    mut len: size_t,
) {
    let mut freespace: size_t = 0;
    let mut usedspace: size_t = 0;
    if len == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    usedspace = ((*context).bitcount[0 as libc::c_int as usize] >> 3 as libc::c_int)
        .wrapping_rem(128 as libc::c_int as libc::c_ulong);
    if usedspace > 0 as libc::c_int as libc::c_ulong {
        freespace = (128 as libc::c_int as libc::c_ulong).wrapping_sub(usedspace);
        if len >= freespace {
            memcpy(
                &mut *((*context).buffer).as_mut_ptr().offset(usedspace as isize) as *mut u_int8_t
                    as *mut libc::c_void,
                data as *const libc::c_void,
                freespace,
            );
            (*context).bitcount[0 as libc::c_int as usize] =
                ((*context).bitcount[0 as libc::c_int as usize] as libc::c_ulong)
                    .wrapping_add(freespace << 3 as libc::c_int) as u_int64_t
                    as u_int64_t;
            if (*context).bitcount[0 as libc::c_int as usize] < freespace << 3 as libc::c_int {
                (*context).bitcount[1 as libc::c_int as usize] =
                    ((*context).bitcount[1 as libc::c_int as usize]).wrapping_add(1);
                (*context).bitcount[1 as libc::c_int as usize];
            }
            len = (len as libc::c_ulong).wrapping_sub(freespace) as size_t as size_t;
            data = data.offset(freespace as isize);
            SHA512Transform(
                ((*context).state.st64).as_mut_ptr(),
                ((*context).buffer).as_mut_ptr() as *const u_int8_t,
            );
        } else {
            memcpy(
                &mut *((*context).buffer).as_mut_ptr().offset(usedspace as isize) as *mut u_int8_t
                    as *mut libc::c_void,
                data as *const libc::c_void,
                len,
            );
            (*context).bitcount[0 as libc::c_int as usize] =
                ((*context).bitcount[0 as libc::c_int as usize] as libc::c_ulong)
                    .wrapping_add(len << 3 as libc::c_int) as u_int64_t
                    as u_int64_t;
            if (*context).bitcount[0 as libc::c_int as usize] < len << 3 as libc::c_int {
                (*context).bitcount[1 as libc::c_int as usize] =
                    ((*context).bitcount[1 as libc::c_int as usize]).wrapping_add(1);
                (*context).bitcount[1 as libc::c_int as usize];
            }
            freespace = 0 as libc::c_int as size_t;
            usedspace = freespace;
            return;
        }
    }
    while len >= 128 as libc::c_int as libc::c_ulong {
        SHA512Transform(((*context).state.st64).as_mut_ptr(), data);
        (*context).bitcount[0 as libc::c_int as usize] =
            ((*context).bitcount[0 as libc::c_int as usize] as libc::c_ulong)
                .wrapping_add(((128 as libc::c_int) << 3 as libc::c_int) as u_int64_t)
                as u_int64_t as u_int64_t;
        if (*context).bitcount[0 as libc::c_int as usize]
            < ((128 as libc::c_int) << 3 as libc::c_int) as libc::c_ulong
        {
            (*context).bitcount[1 as libc::c_int as usize] =
                ((*context).bitcount[1 as libc::c_int as usize]).wrapping_add(1);
            (*context).bitcount[1 as libc::c_int as usize];
        }
        len = (len as libc::c_ulong).wrapping_sub(128 as libc::c_int as libc::c_ulong) as size_t
            as size_t;
        data = data.offset(128 as libc::c_int as isize);
    }
    if len > 0 as libc::c_int as libc::c_ulong {
        memcpy(
            ((*context).buffer).as_mut_ptr() as *mut libc::c_void,
            data as *const libc::c_void,
            len,
        );
        (*context).bitcount[0 as libc::c_int as usize] =
            ((*context).bitcount[0 as libc::c_int as usize] as libc::c_ulong)
                .wrapping_add(len << 3 as libc::c_int) as u_int64_t as u_int64_t;
        if (*context).bitcount[0 as libc::c_int as usize] < len << 3 as libc::c_int {
            (*context).bitcount[1 as libc::c_int as usize] =
                ((*context).bitcount[1 as libc::c_int as usize]).wrapping_add(1);
            (*context).bitcount[1 as libc::c_int as usize];
        }
    }
    freespace = 0 as libc::c_int as size_t;
    usedspace = freespace;
}
#[no_mangle]
pub unsafe extern "C" fn SHA512Pad(mut context: *mut SHA2_CTX) {
    let mut usedspace: libc::c_uint = 0;
    usedspace = ((*context).bitcount[0 as libc::c_int as usize] >> 3 as libc::c_int)
        .wrapping_rem(128 as libc::c_int as libc::c_ulong) as libc::c_uint;
    if usedspace > 0 as libc::c_int as libc::c_uint {
        let fresh17 = usedspace;
        usedspace = usedspace.wrapping_add(1);
        (*context).buffer[fresh17 as usize] = 0x80 as libc::c_int as u_int8_t;
        if usedspace <= (128 as libc::c_int - 16 as libc::c_int) as libc::c_uint {
            memset(
                &mut *((*context).buffer).as_mut_ptr().offset(usedspace as isize) as *mut u_int8_t
                    as *mut libc::c_void,
                0 as libc::c_int,
                ((128 as libc::c_int - 16 as libc::c_int) as libc::c_uint).wrapping_sub(usedspace)
                    as size_t,
            );
        } else {
            if usedspace < 128 as libc::c_int as libc::c_uint {
                memset(
                    &mut *((*context).buffer).as_mut_ptr().offset(usedspace as isize)
                        as *mut u_int8_t as *mut libc::c_void,
                    0 as libc::c_int,
                    (128 as libc::c_int as libc::c_uint).wrapping_sub(usedspace) as size_t,
                );
            }
            SHA512Transform(
                ((*context).state.st64).as_mut_ptr(),
                ((*context).buffer).as_mut_ptr() as *const u_int8_t,
            );
            memset(
                ((*context).buffer).as_mut_ptr() as *mut libc::c_void,
                0 as libc::c_int,
                (128 as libc::c_int - 2 as libc::c_int) as size_t,
            );
        }
    } else {
        memset(
            ((*context).buffer).as_mut_ptr() as *mut libc::c_void,
            0 as libc::c_int,
            (128 as libc::c_int - 16 as libc::c_int) as size_t,
        );
        *((*context).buffer).as_mut_ptr() = 0x80 as libc::c_int as u_int8_t;
    }
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(0 as libc::c_int as isize) =
        ((*context).bitcount[1 as libc::c_int as usize] >> 56 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(1 as libc::c_int as isize) =
        ((*context).bitcount[1 as libc::c_int as usize] >> 48 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(2 as libc::c_int as isize) =
        ((*context).bitcount[1 as libc::c_int as usize] >> 40 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(3 as libc::c_int as isize) =
        ((*context).bitcount[1 as libc::c_int as usize] >> 32 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(4 as libc::c_int as isize) =
        ((*context).bitcount[1 as libc::c_int as usize] >> 24 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(5 as libc::c_int as isize) =
        ((*context).bitcount[1 as libc::c_int as usize] >> 16 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(6 as libc::c_int as isize) =
        ((*context).bitcount[1 as libc::c_int as usize] >> 8 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int) as isize) as *mut u_int8_t)
        .offset(7 as libc::c_int as isize) =
        (*context).bitcount[1 as libc::c_int as usize] as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int + 8 as libc::c_int) as isize)
        as *mut u_int8_t)
        .offset(0 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 56 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int + 8 as libc::c_int) as isize)
        as *mut u_int8_t)
        .offset(1 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 48 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int + 8 as libc::c_int) as isize)
        as *mut u_int8_t)
        .offset(2 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 40 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int + 8 as libc::c_int) as isize)
        as *mut u_int8_t)
        .offset(3 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 32 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int + 8 as libc::c_int) as isize)
        as *mut u_int8_t)
        .offset(4 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 24 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int + 8 as libc::c_int) as isize)
        as *mut u_int8_t)
        .offset(5 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 16 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int + 8 as libc::c_int) as isize)
        as *mut u_int8_t)
        .offset(6 as libc::c_int as isize) =
        ((*context).bitcount[0 as libc::c_int as usize] >> 8 as libc::c_int) as u_int8_t;
    *(&mut *((*context).buffer)
        .as_mut_ptr()
        .offset((128 as libc::c_int - 16 as libc::c_int + 8 as libc::c_int) as isize)
        as *mut u_int8_t)
        .offset(7 as libc::c_int as isize) =
        (*context).bitcount[0 as libc::c_int as usize] as u_int8_t;
    SHA512Transform(
        ((*context).state.st64).as_mut_ptr(),
        ((*context).buffer).as_mut_ptr() as *const u_int8_t,
    );
    usedspace = 0 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn SHA512Final(mut digest: *mut u_int8_t, mut context: *mut SHA2_CTX) {
    SHA512Pad(context);
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 8 as libc::c_int {
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(0 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 56 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(1 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 48 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(2 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 40 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(3 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 32 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(4 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 24 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(5 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 16 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(6 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 8 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(7 as libc::c_int as isize) = (*context).state.st64[i as usize] as u_int8_t;
        i += 1;
        i;
    }
    explicit_bzero(
        context as *mut libc::c_void,
        ::core::mem::size_of::<SHA2_CTX>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn SHA384Init(mut context: *mut SHA2_CTX) {
    memcpy(
        ((*context).state.st64).as_mut_ptr() as *mut libc::c_void,
        sha384_initial_hash_value.as_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[u_int64_t; 8]>() as libc::c_ulong,
    );
    memset(
        ((*context).buffer).as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[u_int8_t; 128]>() as libc::c_ulong,
    );
    (*context).bitcount[1 as libc::c_int as usize] = 0 as libc::c_int as u_int64_t;
    (*context).bitcount[0 as libc::c_int as usize] = (*context).bitcount[1 as libc::c_int as usize];
}
#[no_mangle]
pub unsafe extern "C" fn SHA384Transform(mut state: *mut u_int64_t, mut data: *const u_int8_t) {
    SHA512Transform(state, data);
}
#[no_mangle]
pub unsafe extern "C" fn SHA384Update(
    mut context: *mut SHA2_CTX,
    mut data: *const u_int8_t,
    mut len: size_t,
) {
    SHA512Update(context, data, len);
}
#[no_mangle]
pub unsafe extern "C" fn SHA384Pad(mut context: *mut SHA2_CTX) {
    SHA512Pad(context);
}
#[no_mangle]
pub unsafe extern "C" fn SHA384Final(mut digest: *mut u_int8_t, mut context: *mut SHA2_CTX) {
    SHA384Pad(context);
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 6 as libc::c_int {
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(0 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 56 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(1 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 48 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(2 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 40 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(3 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 32 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(4 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 24 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(5 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 16 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(6 as libc::c_int as isize) =
            ((*context).state.st64[i as usize] >> 8 as libc::c_int) as u_int8_t;
        *digest
            .offset((i * 8 as libc::c_int) as isize)
            .offset(7 as libc::c_int as isize) = (*context).state.st64[i as usize] as u_int8_t;
        i += 1;
        i;
    }
    explicit_bzero(
        context as *mut libc::c_void,
        ::core::mem::size_of::<SHA2_CTX>() as libc::c_ulong,
    );
}
