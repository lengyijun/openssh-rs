use crate::kex::dh_st;
use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type bignum_st;

    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::FILE;
    fn __getdelim(
        __lineptr: *mut *mut libc::c_char,
        __n: *mut size_t,
        __delimiter: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> __ssize_t;
    fn rewind(__stream: *mut libc::FILE);
    fn arc4random_uniform(_: uint32_t) -> uint32_t;

    fn strsep(__stringp: *mut *mut libc::c_char, __delim: *const libc::c_char)
        -> *mut libc::c_char;
    fn BN_hex2bn(a: *mut *mut BIGNUM, str: *const libc::c_char) -> libc::c_int;
    fn BN_is_bit_set(a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_cmp(a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_value_one() -> *const BIGNUM;
    fn BN_num_bits(a: *const BIGNUM) -> libc::c_int;
    fn BN_new() -> *mut BIGNUM;
    fn BN_clear_free(a: *mut BIGNUM);
    fn BN_sub(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_is_negative(b: *const BIGNUM) -> libc::c_int;
    fn DH_set_length(dh: *mut DH, length: libc::c_long) -> libc::c_int;
    fn DH_get0_key(dh: *const DH, pub_key: *mut *const BIGNUM, priv_key: *mut *const BIGNUM);
    fn DH_set0_pqg(dh: *mut DH, p: *mut BIGNUM, q: *mut BIGNUM, g: *mut BIGNUM) -> libc::c_int;
    fn DH_get0_pqg(
        dh: *const DH,
        p: *mut *const BIGNUM,
        q: *mut *const BIGNUM,
        g: *mut *const BIGNUM,
    );
    fn DH_generate_key(dh: *mut DH) -> libc::c_int;
    fn DH_free(dh: *mut DH);
    fn DH_new() -> *mut DH;

    fn strdelim(_: *mut *mut libc::c_char) -> *mut libc::c_char;
}
pub type __u_int = libc::c_uint;
pub type __uint32_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type uint32_t = __uint32_t;

pub type _IO_lock_t = ();

pub type BIGNUM = bignum_st;
pub type DH = dh_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dhgroup {
    pub size: libc::c_int,
    pub g: *mut BIGNUM,
    pub p: *mut BIGNUM,
}
pub type LogLevel = libc::c_int;
pub const SYSLOG_LEVEL_NOT_SET: LogLevel = -1;
pub const SYSLOG_LEVEL_DEBUG3: LogLevel = 7;
pub const SYSLOG_LEVEL_DEBUG2: LogLevel = 6;
pub const SYSLOG_LEVEL_DEBUG1: LogLevel = 5;
pub const SYSLOG_LEVEL_VERBOSE: LogLevel = 4;
pub const SYSLOG_LEVEL_INFO: LogLevel = 3;
pub const SYSLOG_LEVEL_ERROR: LogLevel = 2;
pub const SYSLOG_LEVEL_FATAL: LogLevel = 1;
pub const SYSLOG_LEVEL_QUIET: LogLevel = 0;
#[inline]
unsafe extern "C" fn getline(
    mut __lineptr: *mut *mut libc::c_char,
    mut __n: *mut size_t,
    mut __stream: *mut libc::FILE,
) -> __ssize_t {
    return __getdelim(__lineptr, __n, '\n' as i32, __stream);
}
static mut moduli_filename: *const libc::c_char = 0 as *const libc::c_char;
pub unsafe extern "C" fn dh_set_moduli_file(mut filename: *const libc::c_char) {
    moduli_filename = filename;
}
unsafe extern "C" fn get_moduli_filename() -> *const libc::c_char {
    return if !moduli_filename.is_null() {
        moduli_filename
    } else {
        b"/usr/local/etc/moduli\0" as *const u8 as *const libc::c_char
    };
}
unsafe extern "C" fn parse_prime(
    mut linenum: libc::c_int,
    mut line: *mut libc::c_char,
    mut dhg: *mut dhgroup,
) -> libc::c_int {
    let mut current_block: u64;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut arg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut strsize: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut gen: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut prime: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut errstr: *const libc::c_char = 0 as *const libc::c_char;
    let mut n: libc::c_longlong = 0;
    (*dhg).g = 0 as *mut BIGNUM;
    (*dhg).p = (*dhg).g;
    cp = line;
    arg = strdelim(&mut cp);
    if arg.is_null() {
        return 0 as libc::c_int;
    }
    if *arg as libc::c_int == '\0' as i32 {
        arg = strdelim(&mut cp);
    }
    if arg.is_null() || *arg == 0 || *arg as libc::c_int == '#' as i32 {
        return 0 as libc::c_int;
    }
    if cp.is_null() || *arg as libc::c_int == '\0' as i32 {
        current_block = 12731601281199319562;
    } else {
        arg = strsep(&mut cp, b" \0" as *const u8 as *const libc::c_char);
        if cp.is_null() || *arg as libc::c_int == '\0' as i32 {
            current_block = 12731601281199319562;
        } else {
            n = crate::openbsd_compat::strtonum::strtonum(
                arg,
                0 as libc::c_int as libc::c_longlong,
                5 as libc::c_int as libc::c_longlong,
                &mut errstr,
            );
            if !errstr.is_null() || n != 2 as libc::c_int as libc::c_longlong {
                crate::log::sshlog(
                    b"dh.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"parse_prime\0"))
                        .as_ptr(),
                    87 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"moduli:%d: type is not %d\0" as *const u8 as *const libc::c_char,
                    linenum,
                    2 as libc::c_int,
                );
                current_block = 2143926380268802421;
            } else {
                arg = strsep(&mut cp, b" \0" as *const u8 as *const libc::c_char);
                if cp.is_null() || *arg as libc::c_int == '\0' as i32 {
                    current_block = 12731601281199319562;
                } else {
                    n = crate::openbsd_compat::strtonum::strtonum(
                        arg,
                        0 as libc::c_int as libc::c_longlong,
                        0x1f as libc::c_int as libc::c_longlong,
                        &mut errstr,
                    );
                    if !errstr.is_null()
                        || n & 0x1 as libc::c_int as libc::c_longlong != 0
                        || n & !(0x1 as libc::c_int) as libc::c_longlong == 0
                    {
                        crate::log::sshlog(
                            b"dh.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                b"parse_prime\0",
                            ))
                            .as_ptr(),
                            97 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"moduli:%d: invalid moduli tests flag\0" as *const u8
                                as *const libc::c_char,
                            linenum,
                        );
                        current_block = 2143926380268802421;
                    } else {
                        arg = strsep(&mut cp, b" \0" as *const u8 as *const libc::c_char);
                        if cp.is_null() || *arg as libc::c_int == '\0' as i32 {
                            current_block = 12731601281199319562;
                        } else {
                            n = crate::openbsd_compat::strtonum::strtonum(
                                arg,
                                0 as libc::c_int as libc::c_longlong,
                                ((1 as libc::c_int) << 30 as libc::c_int) as libc::c_longlong,
                                &mut errstr,
                            );
                            if !errstr.is_null() || n == 0 as libc::c_int as libc::c_longlong {
                                crate::log::sshlog(
                                    b"dh.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                        b"parse_prime\0",
                                    ))
                                    .as_ptr(),
                                    105 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"moduli:%d: invalid primality trial count\0" as *const u8
                                        as *const libc::c_char,
                                    linenum,
                                );
                                current_block = 2143926380268802421;
                            } else {
                                strsize =
                                    strsep(&mut cp, b" \0" as *const u8 as *const libc::c_char);
                                if cp.is_null()
                                    || *strsize as libc::c_int == '\0' as i32
                                    || {
                                        (*dhg).size = crate::openbsd_compat::strtonum::strtonum(
                                            strsize,
                                            0 as libc::c_int as libc::c_longlong,
                                            (64 as libc::c_int * 1024 as libc::c_int)
                                                as libc::c_longlong,
                                            &mut errstr,
                                        )
                                            as libc::c_int;
                                        (*dhg).size == 0 as libc::c_int
                                    }
                                    || !errstr.is_null()
                                {
                                    crate::log::sshlog(
                                        b"dh.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                            b"parse_prime\0",
                                        ))
                                        .as_ptr(),
                                        112 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"moduli:%d: invalid prime length\0" as *const u8
                                            as *const libc::c_char,
                                        linenum,
                                    );
                                    current_block = 2143926380268802421;
                                } else {
                                    (*dhg).size += 1;
                                    (*dhg).size;
                                    gen =
                                        strsep(&mut cp, b" \0" as *const u8 as *const libc::c_char);
                                    if cp.is_null() || *gen as libc::c_int == '\0' as i32 {
                                        current_block = 12731601281199319562;
                                    } else {
                                        prime = strsep(
                                            &mut cp,
                                            b" \0" as *const u8 as *const libc::c_char,
                                        );
                                        if !cp.is_null() || *prime as libc::c_int == '\0' as i32 {
                                            current_block = 12731601281199319562;
                                        } else {
                                            (*dhg).g = BN_new();
                                            if ((*dhg).g).is_null() || {
                                                (*dhg).p = BN_new();
                                                ((*dhg).p).is_null()
                                            } {
                                                crate::log::sshlog(
                                                    b"dh.c\0" as *const u8 as *const libc::c_char,
                                                    (*::core::mem::transmute::<
                                                        &[u8; 12],
                                                        &[libc::c_char; 12],
                                                    >(
                                                        b"parse_prime\0"
                                                    ))
                                                    .as_ptr(),
                                                    129 as libc::c_int,
                                                    0 as libc::c_int,
                                                    SYSLOG_LEVEL_ERROR,
                                                    0 as *const libc::c_char,
                                                    b"parse_prime: BN_new failed\0" as *const u8
                                                        as *const libc::c_char,
                                                );
                                            } else if BN_hex2bn(&mut (*dhg).g, gen)
                                                == 0 as libc::c_int
                                            {
                                                crate::log::sshlog(
                                                    b"dh.c\0" as *const u8 as *const libc::c_char,
                                                    (*::core::mem::transmute::<
                                                        &[u8; 12],
                                                        &[libc::c_char; 12],
                                                    >(
                                                        b"parse_prime\0"
                                                    ))
                                                    .as_ptr(),
                                                    133 as libc::c_int,
                                                    0 as libc::c_int,
                                                    SYSLOG_LEVEL_ERROR,
                                                    0 as *const libc::c_char,
                                                    b"moduli:%d: could not parse generator value\0"
                                                        as *const u8
                                                        as *const libc::c_char,
                                                    linenum,
                                                );
                                            } else if BN_hex2bn(&mut (*dhg).p, prime)
                                                == 0 as libc::c_int
                                            {
                                                crate::log::sshlog(
                                                    b"dh.c\0" as *const u8 as *const libc::c_char,
                                                    (*::core::mem::transmute::<
                                                        &[u8; 12],
                                                        &[libc::c_char; 12],
                                                    >(
                                                        b"parse_prime\0"
                                                    ))
                                                    .as_ptr(),
                                                    137 as libc::c_int,
                                                    0 as libc::c_int,
                                                    SYSLOG_LEVEL_ERROR,
                                                    0 as *const libc::c_char,
                                                    b"moduli:%d: could not parse prime value\0"
                                                        as *const u8
                                                        as *const libc::c_char,
                                                    linenum,
                                                );
                                            } else if BN_num_bits((*dhg).p) != (*dhg).size {
                                                crate::log::sshlog(
                                                    b"dh.c\0" as *const u8 as *const libc::c_char,
                                                    (*::core::mem::transmute::<
                                                        &[u8; 12],
                                                        &[libc::c_char; 12],
                                                    >(b"parse_prime\0"))
                                                        .as_ptr(),
                                                    142 as libc::c_int,
                                                    0 as libc::c_int,
                                                    SYSLOG_LEVEL_ERROR,
                                                    0 as *const libc::c_char,
                                                    b"moduli:%d: prime has wrong size: actual %d listed %d\0"
                                                        as *const u8 as *const libc::c_char,
                                                    linenum,
                                                    BN_num_bits((*dhg).p),
                                                    (*dhg).size - 1 as libc::c_int,
                                                );
                                            } else if BN_cmp((*dhg).g, BN_value_one())
                                                <= 0 as libc::c_int
                                            {
                                                crate::log::sshlog(
                                                    b"dh.c\0" as *const u8 as *const libc::c_char,
                                                    (*::core::mem::transmute::<
                                                        &[u8; 12],
                                                        &[libc::c_char; 12],
                                                    >(
                                                        b"parse_prime\0"
                                                    ))
                                                    .as_ptr(),
                                                    146 as libc::c_int,
                                                    0 as libc::c_int,
                                                    SYSLOG_LEVEL_ERROR,
                                                    0 as *const libc::c_char,
                                                    b"moduli:%d: generator is invalid\0"
                                                        as *const u8
                                                        as *const libc::c_char,
                                                    linenum,
                                                );
                                            } else {
                                                return 1 as libc::c_int;
                                            }
                                            current_block = 2143926380268802421;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    match current_block {
        12731601281199319562 => {
            crate::log::sshlog(
                b"dh.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"parse_prime\0"))
                    .as_ptr(),
                123 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"moduli:%d: truncated\0" as *const u8 as *const libc::c_char,
                linenum,
            );
        }
        _ => {}
    }
    BN_clear_free((*dhg).g);
    BN_clear_free((*dhg).p);
    (*dhg).p = 0 as *mut BIGNUM;
    (*dhg).g = (*dhg).p;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn choose_dh(
    mut min: libc::c_int,
    mut wantbits: libc::c_int,
    mut max: libc::c_int,
) -> *mut DH {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut best: libc::c_int = 0;
    let mut bestcount: libc::c_int = 0;
    let mut which: libc::c_int = 0;
    let mut linenum: libc::c_int = 0;
    let mut dhg: dhgroup = dhgroup {
        size: 0,
        g: 0 as *mut BIGNUM,
        p: 0 as *mut BIGNUM,
    };
    f = fopen(
        get_moduli_filename(),
        b"r\0" as *const u8 as *const libc::c_char,
    );
    if f.is_null() {
        crate::log::sshlog(
            b"dh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"choose_dh\0")).as_ptr(),
            169 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"WARNING: could not open %s (%s), using fixed modulus\0" as *const u8
                as *const libc::c_char,
            get_moduli_filename(),
            libc::strerror(*libc::__errno_location()),
        );
        return dh_new_group_fallback(max);
    }
    linenum = 0 as libc::c_int;
    bestcount = 0 as libc::c_int;
    best = bestcount;
    while getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long {
        linenum += 1;
        linenum;
        if parse_prime(linenum, line, &mut dhg) == 0 {
            continue;
        }
        BN_clear_free(dhg.g);
        BN_clear_free(dhg.p);
        if dhg.size > max || dhg.size < min {
            continue;
        }
        if dhg.size > wantbits && dhg.size < best || dhg.size > best && best < wantbits {
            best = dhg.size;
            bestcount = 0 as libc::c_int;
        }
        if dhg.size == best {
            bestcount += 1;
            bestcount;
        }
    }
    libc::free(line as *mut libc::c_void);
    line = 0 as *mut libc::c_char;
    linesize = 0 as libc::c_int as size_t;
    rewind(f);
    if bestcount == 0 as libc::c_int {
        fclose(f);
        crate::log::sshlog(
            b"dh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"choose_dh\0")).as_ptr(),
            201 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"WARNING: no suitable primes in %s\0" as *const u8 as *const libc::c_char,
            get_moduli_filename(),
        );
        return dh_new_group_fallback(max);
    }
    which = arc4random_uniform(bestcount as uint32_t) as libc::c_int;
    linenum = 0 as libc::c_int;
    bestcount = 0 as libc::c_int;
    while getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long {
        linenum += 1;
        linenum;
        if parse_prime(linenum, line, &mut dhg) == 0 {
            continue;
        }
        if !(dhg.size > max || dhg.size < min || dhg.size != best || {
            let fresh0 = bestcount;
            bestcount = bestcount + 1;
            fresh0 != which
        }) {
            break;
        }
        BN_clear_free(dhg.g);
        BN_clear_free(dhg.p);
    }
    libc::free(line as *mut libc::c_void);
    line = 0 as *mut libc::c_char;
    fclose(f);
    if bestcount != which + 1 as libc::c_int {
        crate::log::sshlog(
            b"dh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"choose_dh\0")).as_ptr(),
            226 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"WARNING: selected prime disappeared in %s, giving up\0" as *const u8
                as *const libc::c_char,
            get_moduli_filename(),
        );
        return dh_new_group_fallback(max);
    }
    return dh_new_group(dhg.g, dhg.p);
}
pub unsafe extern "C" fn dh_pub_is_valid(
    mut dh: *const DH,
    mut dh_pub: *const BIGNUM,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut n: libc::c_int = BN_num_bits(dh_pub);
    let mut bits_set: libc::c_int = 0 as libc::c_int;
    let mut tmp: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dh_p: *const BIGNUM = 0 as *const BIGNUM;
    DH_get0_pqg(
        dh,
        &mut dh_p,
        0 as *mut *const BIGNUM,
        0 as *mut *const BIGNUM,
    );
    if BN_is_negative(dh_pub) != 0 {
        crate::log::sshlog(
            b"dh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"dh_pub_is_valid\0"))
                .as_ptr(),
            247 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"invalid public DH value: negative\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if BN_cmp(dh_pub, BN_value_one()) != 1 as libc::c_int {
        crate::log::sshlog(
            b"dh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"dh_pub_is_valid\0"))
                .as_ptr(),
            251 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"invalid public DH value: <= 1\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    tmp = BN_new();
    if tmp.is_null() {
        crate::log::sshlog(
            b"dh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"dh_pub_is_valid\0"))
                .as_ptr(),
            256 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"BN_new failed\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if BN_sub(tmp, dh_p, BN_value_one()) == 0 || BN_cmp(dh_pub, tmp) != -(1 as libc::c_int) {
        BN_clear_free(tmp);
        crate::log::sshlog(
            b"dh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"dh_pub_is_valid\0"))
                .as_ptr(),
            262 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"invalid public DH value: >= p-1\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    BN_clear_free(tmp);
    i = 0 as libc::c_int;
    while i <= n {
        if BN_is_bit_set(dh_pub, i) != 0 {
            bits_set += 1;
            bits_set;
        }
        i += 1;
        i;
    }
    crate::log::sshlog(
        b"dh.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"dh_pub_is_valid\0")).as_ptr(),
        270 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"bits set: %d/%d\0" as *const u8 as *const libc::c_char,
        bits_set,
        BN_num_bits(dh_p),
    );
    if bits_set < 4 as libc::c_int {
        crate::log::sshlog(
            b"dh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"dh_pub_is_valid\0"))
                .as_ptr(),
            277 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"invalid public DH value (%d/%d)\0" as *const u8 as *const libc::c_char,
            bits_set,
            BN_num_bits(dh_p),
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn dh_gen_key(mut dh: *mut DH, mut need: libc::c_int) -> libc::c_int {
    let mut pbits: libc::c_int = 0;
    let mut dh_p: *const BIGNUM = 0 as *const BIGNUM;
    let mut pub_key: *const BIGNUM = 0 as *const BIGNUM;
    DH_get0_pqg(
        dh,
        &mut dh_p,
        0 as *mut *const BIGNUM,
        0 as *mut *const BIGNUM,
    );
    if need < 0 as libc::c_int
        || dh_p.is_null()
        || {
            pbits = BN_num_bits(dh_p);
            pbits <= 0 as libc::c_int
        }
        || need > 2147483647 as libc::c_int / 2 as libc::c_int
        || 2 as libc::c_int * need > pbits
    {
        return -(10 as libc::c_int);
    }
    if need < 256 as libc::c_int {
        need = 256 as libc::c_int;
    }
    if DH_set_length(
        dh,
        (if (need * 2 as libc::c_int) < pbits - 1 as libc::c_int {
            need * 2 as libc::c_int
        } else {
            pbits - 1 as libc::c_int
        }) as libc::c_long,
    ) == 0
    {
        return -(22 as libc::c_int);
    }
    if DH_generate_key(dh) == 0 as libc::c_int {
        return -(22 as libc::c_int);
    }
    DH_get0_key(dh, &mut pub_key, 0 as *mut *const BIGNUM);
    if dh_pub_is_valid(dh, pub_key) == 0 {
        return -(4 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn dh_new_group_asc(
    mut gen: *const libc::c_char,
    mut modulus: *const libc::c_char,
) -> *mut DH {
    let mut dh: *mut DH = 0 as *mut DH;
    let mut dh_p: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut dh_g: *mut BIGNUM = 0 as *mut BIGNUM;
    dh = DH_new();
    if dh.is_null() {
        return 0 as *mut DH;
    }
    if !(BN_hex2bn(&mut dh_p, modulus) == 0 as libc::c_int
        || BN_hex2bn(&mut dh_g, gen) == 0 as libc::c_int)
    {
        if !(DH_set0_pqg(dh, dh_p, 0 as *mut BIGNUM, dh_g) == 0) {
            return dh;
        }
    }
    DH_free(dh);
    BN_clear_free(dh_p);
    BN_clear_free(dh_g);
    return 0 as *mut DH;
}
pub unsafe extern "C" fn dh_new_group(mut gen: *mut BIGNUM, mut modulus: *mut BIGNUM) -> *mut DH {
    let mut dh: *mut DH = 0 as *mut DH;
    dh = DH_new();
    if dh.is_null() {
        return 0 as *mut DH;
    }
    if DH_set0_pqg(dh, modulus, 0 as *mut BIGNUM, gen) == 0 {
        DH_free(dh);
        return 0 as *mut DH;
    }
    return dh;
}
pub unsafe extern "C" fn dh_new_group1() -> *mut DH {
    static mut gen: *mut libc::c_char =
        b"2\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    static mut group1: *mut libc::c_char = b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF\0"
        as *const u8 as *const libc::c_char as *mut libc::c_char;
    return dh_new_group_asc(gen, group1);
}
pub unsafe extern "C" fn dh_new_group14() -> *mut DH {
    static mut gen: *mut libc::c_char =
        b"2\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    static mut group14: *mut libc::c_char = b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF\0"
        as *const u8 as *const libc::c_char as *mut libc::c_char;
    return dh_new_group_asc(gen, group14);
}
pub unsafe extern "C" fn dh_new_group16() -> *mut DH {
    static mut gen: *mut libc::c_char =
        b"2\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    static mut group16: *mut libc::c_char = b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF\0"
        as *const u8 as *const libc::c_char as *mut libc::c_char;
    return dh_new_group_asc(gen, group16);
}
pub unsafe extern "C" fn dh_new_group18() -> *mut DH {
    static mut gen: *mut libc::c_char =
        b"2\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    static mut group18: *mut libc::c_char = b"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C93402849236C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AACC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E438777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F5683423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD922222E04A4037C0713EB57A81A23F0C73473FC646CEA306B4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A364597E899A0255DC164F31CC50846851DF9AB48195DED7EA1B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F924009438B481C6CD7889A002ED5EE382BC9190DA6FC026E479558E4475677E9AA9E3050E2765694DFC81F56E880B96E7160C980DD98EDD3DFFFFFFFFFFFFFFFFF\0"
        as *const u8 as *const libc::c_char as *mut libc::c_char;
    return dh_new_group_asc(gen, group18);
}
pub unsafe extern "C" fn dh_new_group_fallback(mut max: libc::c_int) -> *mut DH {
    crate::log::sshlog(
        b"dh.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"dh_new_group_fallback\0"))
            .as_ptr(),
        474 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"requested max size %d\0" as *const u8 as *const libc::c_char,
        max,
    );
    if max < 3072 as libc::c_int {
        crate::log::sshlog(
            b"dh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"dh_new_group_fallback\0"))
                .as_ptr(),
            476 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"using 2k bit group 14\0" as *const u8 as *const libc::c_char,
        );
        return dh_new_group14();
    } else if max < 6144 as libc::c_int {
        crate::log::sshlog(
            b"dh.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"dh_new_group_fallback\0"))
                .as_ptr(),
            479 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"using 4k bit group 16\0" as *const u8 as *const libc::c_char,
        );
        return dh_new_group16();
    }
    crate::log::sshlog(
        b"dh.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"dh_new_group_fallback\0"))
            .as_ptr(),
        482 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"using 8k bit group 18\0" as *const u8 as *const libc::c_char,
    );
    return dh_new_group18();
}
pub unsafe extern "C" fn dh_estimate(mut bits: libc::c_int) -> u_int {
    if bits <= 112 as libc::c_int {
        return 2048 as libc::c_int as u_int;
    }
    if bits <= 128 as libc::c_int {
        return 3072 as libc::c_int as u_int;
    }
    if bits <= 192 as libc::c_int {
        return 7680 as libc::c_int as u_int;
    }
    return 8192 as libc::c_int as u_int;
}
