use ::libc;
extern "C" {
    pub type ossl_init_settings_st;
    fn OPENSSL_init_crypto(opts: uint64_t, settings: *const OPENSSL_INIT_SETTINGS) -> libc::c_int;
}
pub type __uint64_t = libc::c_ulong;
pub type uint64_t = __uint64_t;
pub type OPENSSL_INIT_SETTINGS = ossl_init_settings_st;
#[no_mangle]
pub unsafe extern "C" fn ssh_compatible_openssl(
    mut headerver: libc::c_long,
    mut libver: libc::c_long,
) -> libc::c_int {
    let mut mask: libc::c_long = 0;
    let mut hfix: libc::c_long = 0;
    let mut lfix: libc::c_long = 0;
    if headerver == libver {
        return 1 as libc::c_int;
    }
    if headerver >= 0x3000000f as libc::c_int as libc::c_long {
        mask = 0xf000000f as libc::c_long;
        return (headerver & mask == libver & mask) as libc::c_int;
    }
    mask = 0xfff0000f as libc::c_long;
    hfix = (headerver & 0xff000 as libc::c_int as libc::c_long) >> 12 as libc::c_int;
    lfix = (libver & 0xff000 as libc::c_int as libc::c_long) >> 12 as libc::c_int;
    if headerver & mask == libver & mask && lfix >= hfix {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn ssh_libcrypto_init() {
    OPENSSL_init_crypto(
        (0x4 as libc::c_long | 0x8 as libc::c_long) as uint64_t,
        0 as *const OPENSSL_INIT_SETTINGS,
    );
}
