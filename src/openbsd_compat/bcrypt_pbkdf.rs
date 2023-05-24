use ::libc;
extern "C" {
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn arc4random_buf(_: *mut libc::c_void, _: size_t);
    fn Blowfish_stream2word(_: *const u_int8_t, _: u_int16_t, _: *mut u_int16_t) -> u_int32_t;
    fn blf_enc(_: *mut blf_ctx, _: *mut u_int32_t, _: u_int16_t);
    fn Blowfish_initstate(_: *mut blf_ctx);
    fn Blowfish_expand0state(_: *mut blf_ctx, _: *const u_int8_t, _: u_int16_t);
    fn Blowfish_expandstate(
        _: *mut blf_ctx,
        _: *const u_int8_t,
        _: u_int16_t,
        _: *const u_int8_t,
        _: u_int16_t,
    );
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn crypto_hash_sha512(
        _: *mut libc::c_uchar,
        _: *const libc::c_uchar,
        _: libc::c_ulonglong,
    ) -> libc::c_int;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type size_t = libc::c_ulong;
pub type u_int8_t = __uint8_t;
pub type u_int16_t = __uint16_t;
pub type u_int32_t = __uint32_t;
pub type uint32_t = __uint32_t;
pub type uint16_t = __uint16_t;
pub type uint8_t = __uint8_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct BlowfishContext {
    pub S: [[u_int32_t; 256]; 4],
    pub P: [u_int32_t; 18],
}
pub type blf_ctx = BlowfishContext;
unsafe extern "C" fn bcrypt_hash(
    mut sha2pass: *mut uint8_t,
    mut sha2salt: *mut uint8_t,
    mut out: *mut uint8_t,
) {
    let mut state: blf_ctx = blf_ctx {
        S: [[0; 256]; 4],
        P: [0; 18],
    };
    let mut ciphertext: [uint8_t; 32] = *::core::mem::transmute::<&[u8; 32], &mut [uint8_t; 32]>(
        b"OxychromaticBlowfishSwatDynamite",
    );
    let mut cdata: [uint32_t; 8] = [0; 8];
    let mut i: libc::c_int = 0;
    let mut j: uint16_t = 0;
    let mut shalen: size_t = 64 as libc::c_uint as size_t;
    Blowfish_initstate(&mut state);
    Blowfish_expandstate(
        &mut state,
        sha2salt,
        shalen as u_int16_t,
        sha2pass,
        shalen as u_int16_t,
    );
    i = 0 as libc::c_int;
    while i < 64 as libc::c_int {
        Blowfish_expand0state(&mut state, sha2salt, shalen as u_int16_t);
        Blowfish_expand0state(&mut state, sha2pass, shalen as u_int16_t);
        i += 1;
        i;
    }
    j = 0 as libc::c_int as uint16_t;
    i = 0 as libc::c_int;
    while i < 8 as libc::c_int {
        cdata[i as usize] = Blowfish_stream2word(
            ciphertext.as_mut_ptr(),
            ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong as u_int16_t,
            &mut j,
        );
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < 64 as libc::c_int {
        blf_enc(
            &mut state,
            cdata.as_mut_ptr(),
            (8 as libc::c_int / 2 as libc::c_int) as u_int16_t,
        );
        i += 1;
        i;
    }
    i = 0 as libc::c_int;
    while i < 8 as libc::c_int {
        *out.offset((4 as libc::c_int * i + 3 as libc::c_int) as isize) =
            (cdata[i as usize] >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint)
                as uint8_t;
        *out.offset((4 as libc::c_int * i + 2 as libc::c_int) as isize) =
            (cdata[i as usize] >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint)
                as uint8_t;
        *out.offset((4 as libc::c_int * i + 1 as libc::c_int) as isize) =
            (cdata[i as usize] >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint)
                as uint8_t;
        *out.offset((4 as libc::c_int * i + 0 as libc::c_int) as isize) =
            (cdata[i as usize] & 0xff as libc::c_int as libc::c_uint) as uint8_t;
        i += 1;
        i;
    }
    explicit_bzero(
        ciphertext.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
    );
    explicit_bzero(
        cdata.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[uint32_t; 8]>() as libc::c_ulong,
    );
    explicit_bzero(
        &mut state as *mut blf_ctx as *mut libc::c_void,
        ::core::mem::size_of::<blf_ctx>() as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn bcrypt_pbkdf(
    mut pass: *const libc::c_char,
    mut passlen: size_t,
    mut salt: *const uint8_t,
    mut saltlen: size_t,
    mut key: *mut uint8_t,
    mut keylen: size_t,
    mut rounds: libc::c_uint,
) -> libc::c_int {
    let mut sha2pass: [uint8_t; 64] = [0; 64];
    let mut sha2salt: [uint8_t; 64] = [0; 64];
    let mut out: [uint8_t; 32] = [0; 32];
    let mut tmpout: [uint8_t; 32] = [0; 32];
    let mut countsalt: *mut uint8_t = 0 as *mut uint8_t;
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut amt: size_t = 0;
    let mut stride: size_t = 0;
    let mut count: uint32_t = 0;
    let mut origkeylen: size_t = keylen;
    if !(rounds < 1 as libc::c_int as libc::c_uint) {
        if !(passlen == 0 as libc::c_int as libc::c_ulong
            || saltlen == 0 as libc::c_int as libc::c_ulong
            || keylen == 0 as libc::c_int as libc::c_ulong
            || keylen
                > (::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong)
                    .wrapping_mul(::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong)
            || saltlen > ((1 as libc::c_int) << 20 as libc::c_int) as libc::c_ulong)
        {
            countsalt = calloc(
                1 as libc::c_int as libc::c_ulong,
                saltlen.wrapping_add(4 as libc::c_int as libc::c_ulong),
            ) as *mut uint8_t;
            if !countsalt.is_null() {
                stride = keylen
                    .wrapping_add(::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    .wrapping_div(::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong);
                amt = keylen
                    .wrapping_add(stride)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    .wrapping_div(stride);
                memcpy(
                    countsalt as *mut libc::c_void,
                    salt as *const libc::c_void,
                    saltlen,
                );
                crypto_hash_sha512(
                    sha2pass.as_mut_ptr(),
                    pass as *const libc::c_uchar,
                    passlen as libc::c_ulonglong,
                );
                count = 1 as libc::c_int as uint32_t;
                while keylen > 0 as libc::c_int as libc::c_ulong {
                    *countsalt
                        .offset(saltlen.wrapping_add(0 as libc::c_int as libc::c_ulong) as isize) =
                        (count >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint)
                            as uint8_t;
                    *countsalt
                        .offset(saltlen.wrapping_add(1 as libc::c_int as libc::c_ulong) as isize) =
                        (count >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint)
                            as uint8_t;
                    *countsalt
                        .offset(saltlen.wrapping_add(2 as libc::c_int as libc::c_ulong) as isize) =
                        (count >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as uint8_t;
                    *countsalt
                        .offset(saltlen.wrapping_add(3 as libc::c_int as libc::c_ulong) as isize) =
                        (count & 0xff as libc::c_int as libc::c_uint) as uint8_t;
                    crypto_hash_sha512(
                        sha2salt.as_mut_ptr(),
                        countsalt,
                        saltlen.wrapping_add(4 as libc::c_int as libc::c_ulong)
                            as libc::c_ulonglong,
                    );
                    bcrypt_hash(
                        sha2pass.as_mut_ptr(),
                        sha2salt.as_mut_ptr(),
                        tmpout.as_mut_ptr(),
                    );
                    memcpy(
                        out.as_mut_ptr() as *mut libc::c_void,
                        tmpout.as_mut_ptr() as *const libc::c_void,
                        ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
                    );
                    i = 1 as libc::c_int as size_t;
                    while i < rounds as libc::c_ulong {
                        crypto_hash_sha512(
                            sha2salt.as_mut_ptr(),
                            tmpout.as_mut_ptr(),
                            ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong
                                as libc::c_ulonglong,
                        );
                        bcrypt_hash(
                            sha2pass.as_mut_ptr(),
                            sha2salt.as_mut_ptr(),
                            tmpout.as_mut_ptr(),
                        );
                        j = 0 as libc::c_int as size_t;
                        while j < ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong {
                            out[j as usize] = (out[j as usize] as libc::c_int
                                ^ tmpout[j as usize] as libc::c_int)
                                as uint8_t;
                            j = j.wrapping_add(1);
                            j;
                        }
                        i = i.wrapping_add(1);
                        i;
                    }
                    amt = if amt < keylen { amt } else { keylen };
                    i = 0 as libc::c_int as size_t;
                    while i < amt {
                        let mut dest: size_t = i
                            .wrapping_mul(stride)
                            .wrapping_add(count.wrapping_sub(1 as libc::c_int as libc::c_uint)
                                as libc::c_ulong);
                        if dest >= origkeylen {
                            break;
                        }
                        *key.offset(dest as isize) = out[i as usize];
                        i = i.wrapping_add(1);
                        i;
                    }
                    keylen = (keylen as libc::c_ulong).wrapping_sub(i) as size_t as size_t;
                    count = count.wrapping_add(1);
                    count;
                }
                freezero(
                    countsalt as *mut libc::c_void,
                    saltlen.wrapping_add(4 as libc::c_int as libc::c_ulong),
                );
                explicit_bzero(
                    out.as_mut_ptr() as *mut libc::c_void,
                    ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
                );
                explicit_bzero(
                    tmpout.as_mut_ptr() as *mut libc::c_void,
                    ::core::mem::size_of::<[uint8_t; 32]>() as libc::c_ulong,
                );
                return 0 as libc::c_int;
            }
        }
    }
    arc4random_buf(key as *mut libc::c_void, keylen);
    return -(1 as libc::c_int);
}
