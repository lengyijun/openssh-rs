use ::libc;
extern "C" {

    pub type bignum_st;
    pub type bignum_ctx;

    pub type ec_group_st;
    pub type ec_point_st;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn BN_num_bits(a: *const BIGNUM) -> libc::c_int;
    fn BN_new() -> *mut BIGNUM;
    fn BN_clear_free(a: *mut BIGNUM);
    fn BN_bin2bn(s: *const libc::c_uchar, len: libc::c_int, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_bn2bin(a: *const BIGNUM, to: *mut libc::c_uchar) -> libc::c_int;
    fn EC_KEY_set_public_key(
        key: *mut crate::sshkey::EC_KEY,
        pub_0: *const EC_POINT,
    ) -> libc::c_int;
    fn EC_KEY_get0_public_key(key: *const crate::sshkey::EC_KEY) -> *const EC_POINT;
    fn EC_KEY_get0_group(key: *const crate::sshkey::EC_KEY) -> *const EC_GROUP;
    fn EC_POINT_new(group: *const EC_GROUP) -> *mut EC_POINT;
    fn EC_POINT_free(point: *mut EC_POINT);
    fn EC_POINT_point2oct(
        group: *const EC_GROUP,
        p: *const EC_POINT,
        form: point_conversion_form_t,
        buf: *mut libc::c_uchar,
        len: size_t,
        ctx: *mut BN_CTX,
    ) -> size_t;
    fn EC_POINT_oct2point(
        group: *const EC_GROUP,
        p: *mut EC_POINT,
        buf: *const libc::c_uchar,
        len: size_t,
        ctx: *mut BN_CTX,
    ) -> libc::c_int;

    fn sshbuf_get_string_direct(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_peek_string_direct(
        buf: *const crate::sshbuf::sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_bignum2_bytes_direct(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type u_char = __u_char;
pub type size_t = libc::c_ulong;
pub type BIGNUM = bignum_st;
pub type BN_CTX = bignum_ctx;

pub type point_conversion_form_t = libc::c_uint;
pub const POINT_CONVERSION_HYBRID: point_conversion_form_t = 6;
pub const POINT_CONVERSION_UNCOMPRESSED: point_conversion_form_t = 4;
pub const POINT_CONVERSION_COMPRESSED: point_conversion_form_t = 2;
pub type EC_GROUP = ec_group_st;
pub type EC_POINT = ec_point_st;
pub unsafe extern "C" fn sshbuf_get_bignum2(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut valp: *mut *mut BIGNUM,
) -> libc::c_int {
    let mut v: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut d: *const u_char = 0 as *const u_char;
    let mut len: size_t = 0;
    let mut r: libc::c_int = 0;
    if !valp.is_null() {
        *valp = 0 as *mut BIGNUM;
    }
    r = sshbuf_get_bignum2_bytes_direct(buf, &mut d, &mut len);
    if r != 0 as libc::c_int {
        return r;
    }
    if !valp.is_null() {
        v = BN_new();
        if v.is_null() || (BN_bin2bn(d, len as libc::c_int, v)).is_null() {
            BN_clear_free(v);
            return -(2 as libc::c_int);
        }
        *valp = v;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn get_ec(
    mut d: *const u_char,
    mut len: size_t,
    mut v: *mut EC_POINT,
    mut g: *const EC_GROUP,
) -> libc::c_int {
    if len == 0 as libc::c_int as libc::c_ulong
        || len
            > (528 as libc::c_int * 2 as libc::c_int / 8 as libc::c_int + 1 as libc::c_int)
                as libc::c_ulong
    {
        return -(8 as libc::c_int);
    }
    if *d as libc::c_int != POINT_CONVERSION_UNCOMPRESSED as libc::c_int {
        return -(4 as libc::c_int);
    }
    if !v.is_null() && EC_POINT_oct2point(g, v, d, len, 0 as *mut BN_CTX) != 1 as libc::c_int {
        return -(4 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_get_ec(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut v: *mut EC_POINT,
    mut g: *const EC_GROUP,
) -> libc::c_int {
    let mut d: *const u_char = 0 as *const u_char;
    let mut len: size_t = 0;
    let mut r: libc::c_int = 0;
    r = sshbuf_peek_string_direct(buf, &mut d, &mut len);
    if r < 0 as libc::c_int {
        return r;
    }
    r = get_ec(d, len, v, g);
    if r != 0 as libc::c_int {
        return r;
    }
    if sshbuf_get_string_direct(buf, 0 as *mut *const u_char, 0 as *mut size_t) != 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_get_eckey(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut v: *mut crate::sshkey::EC_KEY,
) -> libc::c_int {
    let mut pt: *mut EC_POINT = EC_POINT_new(EC_KEY_get0_group(v));
    let mut r: libc::c_int = 0;
    let mut d: *const u_char = 0 as *const u_char;
    let mut len: size_t = 0;
    if pt.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_peek_string_direct(buf, &mut d, &mut len);
    if r < 0 as libc::c_int {
        EC_POINT_free(pt);
        return r;
    }
    r = get_ec(d, len, pt, EC_KEY_get0_group(v));
    if r != 0 as libc::c_int {
        EC_POINT_free(pt);
        return r;
    }
    if EC_KEY_set_public_key(v, pt) != 1 as libc::c_int {
        EC_POINT_free(pt);
        return -(2 as libc::c_int);
    }
    EC_POINT_free(pt);
    if sshbuf_get_string_direct(buf, 0 as *mut *const u_char, 0 as *mut size_t) != 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_put_bignum2(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut v: *const BIGNUM,
) -> libc::c_int {
    let mut d: [u_char; 2049] = [0; 2049];
    let mut len: libc::c_int = (BN_num_bits(v) + 7 as libc::c_int) / 8 as libc::c_int;
    let mut prepend: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    if len < 0 as libc::c_int || len > 16384 as libc::c_int / 8 as libc::c_int {
        return -(10 as libc::c_int);
    }
    *d.as_mut_ptr() = '\0' as i32 as u_char;
    if BN_bn2bin(v, d.as_mut_ptr().offset(1 as libc::c_int as isize)) != len {
        return -(1 as libc::c_int);
    }
    if len > 0 as libc::c_int
        && d[1 as libc::c_int as usize] as libc::c_int & 0x80 as libc::c_int != 0 as libc::c_int
    {
        prepend = 1 as libc::c_int;
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_string(
        buf,
        d.as_mut_ptr()
            .offset(1 as libc::c_int as isize)
            .offset(-(prepend as isize)) as *const libc::c_void,
        (len + prepend) as size_t,
    );
    if r < 0 as libc::c_int {
        explicit_bzero(
            d.as_mut_ptr() as *mut libc::c_void,
            ::core::mem::size_of::<[u_char; 2049]>() as libc::c_ulong,
        );
        return r;
    }
    explicit_bzero(
        d.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_char; 2049]>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshbuf_put_ec(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut v: *const EC_POINT,
    mut g: *const EC_GROUP,
) -> libc::c_int {
    let mut d: [u_char; 133] = [0; 133];
    let mut len: size_t = 0;
    let mut ret: libc::c_int = 0;
    len = EC_POINT_point2oct(
        g,
        v,
        POINT_CONVERSION_UNCOMPRESSED,
        0 as *mut libc::c_uchar,
        0 as libc::c_int as size_t,
        0 as *mut BN_CTX,
    );
    if len
        > (528 as libc::c_int * 2 as libc::c_int / 8 as libc::c_int + 1 as libc::c_int)
            as libc::c_ulong
    {
        return -(10 as libc::c_int);
    }
    if EC_POINT_point2oct(
        g,
        v,
        POINT_CONVERSION_UNCOMPRESSED,
        d.as_mut_ptr(),
        len,
        0 as *mut BN_CTX,
    ) != len
    {
        return -(1 as libc::c_int);
    }
    ret = crate::sshbuf_getput_basic::sshbuf_put_string(
        buf,
        d.as_mut_ptr() as *const libc::c_void,
        len,
    );
    explicit_bzero(d.as_mut_ptr() as *mut libc::c_void, len);
    return ret;
}
pub unsafe extern "C" fn sshbuf_put_eckey(
    mut buf: *mut crate::sshbuf::sshbuf,
    mut v: *const crate::sshkey::EC_KEY,
) -> libc::c_int {
    return sshbuf_put_ec(buf, EC_KEY_get0_public_key(v), EC_KEY_get0_group(v));
}
