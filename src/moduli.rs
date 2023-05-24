use ::libc;
use libc::close;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type bignum_st;
    pub type bignum_ctx;
    pub type bn_gencb_st;
    fn __errno_location() -> *mut libc::c_int;
    
    fn unlink(__name: *const libc::c_char) -> libc::c_int;
    fn rename(__old: *const libc::c_char, __new: *const libc::c_char) -> libc::c_int;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn fdopen(__fd: libc::c_int, __modes: *const libc::c_char) -> *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn fscanf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn fgets(__s: *mut libc::c_char, __n: libc::c_int, __stream: *mut FILE) -> *mut libc::c_char;
    fn fseek(__stream: *mut FILE, __off: libc::c_long, __whence: libc::c_int) -> libc::c_int;
    fn rewind(__stream: *mut FILE);
    fn _ssh_mkstemp(_: *mut libc::c_char) -> libc::c_int;
    fn BN_is_prime_ex(
        p: *const BIGNUM,
        nchecks: libc::c_int,
        ctx: *mut BN_CTX,
        cb: *mut BN_GENCB,
    ) -> libc::c_int;
    fn BN_hex2bn(a: *mut *mut BIGNUM, str: *const libc::c_char) -> libc::c_int;
    fn BN_bn2hex(a: *const BIGNUM) -> *mut libc::c_char;
    fn BN_set_bit(a: *mut BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_rshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_print_fp(fp: *mut FILE, a: *const BIGNUM) -> libc::c_int;
    fn BN_lshift(r: *mut BIGNUM, a: *const BIGNUM, n: libc::c_int) -> libc::c_int;
    fn BN_free(a: *mut BIGNUM);
    fn BN_set_word(a: *mut BIGNUM, w: libc::c_ulong) -> libc::c_int;
    fn BN_add_word(a: *mut BIGNUM, w: libc::c_ulong) -> libc::c_int;
    fn BN_mod_word(a: *const BIGNUM, w: libc::c_ulong) -> libc::c_ulong;
    fn BN_add(r: *mut BIGNUM, a: *const BIGNUM, b: *const BIGNUM) -> libc::c_int;
    fn BN_copy(a: *mut BIGNUM, b: *const BIGNUM) -> *mut BIGNUM;
    fn BN_new() -> *mut BIGNUM;
    fn BN_num_bits(a: *const BIGNUM) -> libc::c_int;
    fn BN_rand(
        rnd: *mut BIGNUM,
        bits: libc::c_int,
        top: libc::c_int,
        bottom: libc::c_int,
    ) -> libc::c_int;
    fn strtoul(_: *const libc::c_char, _: *mut *mut libc::c_char, _: libc::c_int) -> libc::c_ulong;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn time(__timer: *mut time_t) -> time_t;
    fn gmtime(__timer: *const time_t) -> *mut tm;
    fn ctime(__timer: *const time_t) -> *mut libc::c_char;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn xmalloc(_: size_t) -> *mut libc::c_void;
    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn sshlog(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
        _: LogLevel,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: ...
    );
    fn sshfatal(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
        _: LogLevel,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: ...
    ) -> !;
    fn monotime() -> time_t;
}
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type BIGNUM = bignum_st;
pub type BN_CTX = bignum_ctx;
pub type BN_GENCB = bn_gencb_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub tm_gmtoff: libc::c_long,
    pub tm_zone: *const libc::c_char,
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
static mut TinySieve: *mut u_int32_t = 0 as *const u_int32_t as *mut u_int32_t;
static mut tinybits: u_int32_t = 0;
static mut SmallSieve: *mut u_int32_t = 0 as *const u_int32_t as *mut u_int32_t;
static mut smallbits: u_int32_t = 0;
static mut smallbase: u_int32_t = 0;
static mut LargeSieve: *mut u_int32_t = 0 as *const u_int32_t as *mut u_int32_t;
static mut largewords: u_int32_t = 0;
static mut largetries: u_int32_t = 0;
static mut largenumbers: u_int32_t = 0;
static mut largebits: u_int32_t = 0;
static mut largememory: u_int32_t = 0;
static mut largebase: *mut BIGNUM = 0 as *const BIGNUM as *mut BIGNUM;
unsafe extern "C" fn qfileout(
    mut ofile: *mut FILE,
    mut otype: u_int32_t,
    mut otests: u_int32_t,
    mut otries: u_int32_t,
    mut osize: u_int32_t,
    mut ogenerator: u_int32_t,
    mut omodulus: *mut BIGNUM,
) -> libc::c_int {
    let mut gtm: *mut tm = 0 as *mut tm;
    let mut time_now: time_t = 0;
    let mut res: libc::c_int = 0;
    time(&mut time_now);
    gtm = gmtime(&mut time_now);
    if gtm.is_null() {
        return -(1 as libc::c_int);
    }
    res = fprintf(
        ofile,
        b"%04d%02d%02d%02d%02d%02d %u %u %u %u %x \0" as *const u8 as *const libc::c_char,
        (*gtm).tm_year + 1900 as libc::c_int,
        (*gtm).tm_mon + 1 as libc::c_int,
        (*gtm).tm_mday,
        (*gtm).tm_hour,
        (*gtm).tm_min,
        (*gtm).tm_sec,
        otype,
        otests,
        otries,
        osize,
        ogenerator,
    );
    if res < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if BN_print_fp(ofile, omodulus) < 1 as libc::c_int {
        return -(1 as libc::c_int);
    }
    res = fprintf(ofile, b"\n\0" as *const u8 as *const libc::c_char);
    fflush(ofile);
    return if res > 0 as libc::c_int {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
unsafe extern "C" fn sieve_large(mut s32: u_int32_t) {
    let mut r: u_int64_t = 0;
    let mut u: u_int64_t = 0;
    let mut s: u_int64_t = s32 as u_int64_t;
    sshlog(
        b"moduli.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"sieve_large\0")).as_ptr(),
        191 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"sieve_large %u\0" as *const u8 as *const libc::c_char,
        s32,
    );
    largetries = largetries.wrapping_add(1);
    largetries;
    r = BN_mod_word(largebase, s32 as libc::c_ulong);
    if r == 0 as libc::c_int as libc::c_ulong {
        u = 0 as libc::c_int as u_int64_t;
    } else {
        u = s.wrapping_sub(r);
    }
    if (u as libc::c_ulonglong)
        < (largebits as libc::c_ulonglong).wrapping_mul(2 as libc::c_ulonglong)
    {
        if u & 0x1 as libc::c_int as libc::c_ulong != 0 {
            u = (u as libc::c_ulong).wrapping_add(s) as u_int64_t as u_int64_t;
        }
        u = (u as libc::c_ulong).wrapping_div(2 as libc::c_int as libc::c_ulong) as u_int64_t
            as u_int64_t;
        while u < largebits as libc::c_ulong {
            let ref mut fresh0 =
                *LargeSieve.offset((u >> 3 as libc::c_int + 2 as libc::c_int) as isize);
            *fresh0 = (*fresh0 as libc::c_long
                | (1 as libc::c_long) << (u & 31 as libc::c_int as libc::c_ulong))
                as u_int32_t;
            u = (u as libc::c_ulong).wrapping_add(s) as u_int64_t as u_int64_t;
        }
    }
    r = (2 as libc::c_int as libc::c_ulong)
        .wrapping_mul(r)
        .wrapping_add(1 as libc::c_int as libc::c_ulong)
        .wrapping_rem(s);
    if r == 0 as libc::c_int as libc::c_ulong {
        u = 0 as libc::c_int as u_int64_t;
    } else {
        u = s.wrapping_sub(r);
    }
    if (u as libc::c_ulonglong)
        < (largebits as libc::c_ulonglong).wrapping_mul(4 as libc::c_ulonglong)
    {
        while u & 0x3 as libc::c_int as libc::c_ulong != 0 {
            if (0xffffffff as libc::c_ulong).wrapping_sub(u) < s {
                return;
            }
            u = (u as libc::c_ulong).wrapping_add(s) as u_int64_t as u_int64_t;
        }
        u = (u as libc::c_ulong).wrapping_div(4 as libc::c_int as libc::c_ulong) as u_int64_t
            as u_int64_t;
        while u < largebits as libc::c_ulong {
            let ref mut fresh1 =
                *LargeSieve.offset((u >> 3 as libc::c_int + 2 as libc::c_int) as isize);
            *fresh1 = (*fresh1 as libc::c_long
                | (1 as libc::c_long) << (u & 31 as libc::c_int as libc::c_ulong))
                as u_int32_t;
            u = (u as libc::c_ulong).wrapping_add(s) as u_int64_t as u_int64_t;
        }
    }
}
pub unsafe extern "C" fn gen_candidates(
    mut out: *mut FILE,
    mut memory: u_int32_t,
    mut power: u_int32_t,
    mut start: *mut BIGNUM,
) -> libc::c_int {
    let mut q: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut j: u_int32_t = 0;
    let mut r: u_int32_t = 0;
    let mut s: u_int32_t = 0;
    let mut t: u_int32_t = 0;
    let mut smallwords: u_int32_t =
        ((1 as libc::c_ulong) << 16 as libc::c_int >> 6 as libc::c_int) as u_int32_t;
    let mut tinywords: u_int32_t =
        ((1 as libc::c_ulong) << 16 as libc::c_int >> 6 as libc::c_int) as u_int32_t;
    let mut time_start: time_t = 0;
    let mut time_stop: time_t = 0;
    let mut i: u_int32_t = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    largememory = memory;
    if memory != 0 as libc::c_int as libc::c_uint
        && ((memory as libc::c_ulong) < 8 as libc::c_ulong
            || memory as libc::c_ulong > 127 as libc::c_ulong)
    {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0"))
                .as_ptr(),
            260 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Invalid memory amount (min %ld, max %ld)\0" as *const u8 as *const libc::c_char,
            8 as libc::c_ulong,
            127 as libc::c_ulong,
        );
        return -(1 as libc::c_int);
    }
    if power as libc::c_ulong > (1 as libc::c_ulong) << 16 as libc::c_int {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0"))
                .as_ptr(),
            269 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Too many bits: %u > %lu\0" as *const u8 as *const libc::c_char,
            power,
            (1 as libc::c_ulong) << 16 as libc::c_int,
        );
        return -(1 as libc::c_int);
    } else if power < (511 as libc::c_int + 1 as libc::c_int) as libc::c_uint {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0"))
                .as_ptr(),
            272 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Too few bits: %u < %u\0" as *const u8 as *const libc::c_char,
            power,
            511 as libc::c_int + 1 as libc::c_int,
        );
        return -(1 as libc::c_int);
    }
    power = power.wrapping_sub(1);
    power;
    largewords =
        power.wrapping_mul(power) >> 3 as libc::c_int + 2 as libc::c_int - 3 as libc::c_int;
    if largememory as libc::c_ulong > 127 as libc::c_ulong {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0"))
                .as_ptr(),
            291 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Limited memory: %u MB; limit %lu MB\0" as *const u8 as *const libc::c_char,
            largememory,
            127 as libc::c_ulong,
        );
        largememory = 127 as libc::c_ulong as u_int32_t;
    }
    if largewords <= largememory << 20 as libc::c_int - 2 as libc::c_int {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0"))
                .as_ptr(),
            297 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Increased memory: %u MB; need %u bytes\0" as *const u8 as *const libc::c_char,
            largememory,
            largewords << 2 as libc::c_int,
        );
        largewords = largememory << 20 as libc::c_int - 2 as libc::c_int;
    } else if largememory > 0 as libc::c_int as libc::c_uint {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0"))
                .as_ptr(),
            301 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Decreased memory: %u MB; want %u bytes\0" as *const u8 as *const libc::c_char,
            largememory,
            largewords << 2 as libc::c_int,
        );
        largewords = largememory << 20 as libc::c_int - 2 as libc::c_int;
    }
    TinySieve = xcalloc(
        tinywords as size_t,
        ::core::mem::size_of::<u_int32_t>() as libc::c_ulong,
    ) as *mut u_int32_t;
    tinybits = tinywords << 3 as libc::c_int + 2 as libc::c_int;
    SmallSieve = xcalloc(
        smallwords as size_t,
        ::core::mem::size_of::<u_int32_t>() as libc::c_ulong,
    ) as *mut u_int32_t;
    smallbits = smallwords << 3 as libc::c_int + 2 as libc::c_int;
    loop {
        LargeSieve = calloc(
            largewords as libc::c_ulong,
            ::core::mem::size_of::<u_int32_t>() as libc::c_ulong,
        ) as *mut u_int32_t;
        if !LargeSieve.is_null() {
            break;
        }
        largewords = (largewords as libc::c_long
            - ((1 as libc::c_long) << 20 as libc::c_int - 2 as libc::c_int - 2 as libc::c_int))
            as u_int32_t;
    }
    largebits = largewords << 3 as libc::c_int + 2 as libc::c_int;
    largenumbers = largebits.wrapping_mul(2 as libc::c_int as libc::c_uint);
    largetries = 0 as libc::c_int as u_int32_t;
    q = BN_new();
    if q.is_null() {
        sshfatal(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0"))
                .as_ptr(),
            323 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"BN_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    largebase = BN_new();
    if largebase.is_null() {
        sshfatal(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0"))
                .as_ptr(),
            330 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"BN_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    if start.is_null() {
        if BN_rand(
            largebase,
            power as libc::c_int,
            1 as libc::c_int,
            1 as libc::c_int,
        ) == 0 as libc::c_int
        {
            sshfatal(
                b"moduli.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0"))
                    .as_ptr(),
                333 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"BN_rand failed\0" as *const u8 as *const libc::c_char,
            );
        }
    } else if (BN_copy(largebase, start)).is_null() {
        sshfatal(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0"))
                .as_ptr(),
            336 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"BN_copy: failed\0" as *const u8 as *const libc::c_char,
        );
    }
    if BN_set_bit(largebase, 0 as libc::c_int) == 0 as libc::c_int {
        sshfatal(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0"))
                .as_ptr(),
            341 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"BN_set_bit: failed\0" as *const u8 as *const libc::c_char,
        );
    }
    time(&mut time_start);
    sshlog(
        b"moduli.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0")).as_ptr(),
        346 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"%.24s Sieve next %u plus %u-bit\0" as *const u8 as *const libc::c_char,
        ctime(&mut time_start),
        largenumbers,
        power,
    );
    sshlog(
        b"moduli.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0")).as_ptr(),
        347 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"start point: 0x%s\0" as *const u8 as *const libc::c_char,
        BN_bn2hex(largebase),
    );
    i = 0 as libc::c_int as u_int32_t;
    while i < tinybits {
        if !(*TinySieve.offset((i >> 3 as libc::c_int + 2 as libc::c_int) as isize) as libc::c_long
            & (1 as libc::c_long) << (i & 31 as libc::c_int as libc::c_uint)
            != 0)
        {
            t = (2 as libc::c_int as libc::c_uint)
                .wrapping_mul(i)
                .wrapping_add(3 as libc::c_int as libc::c_uint);
            j = i.wrapping_add(t);
            while j < tinybits {
                let ref mut fresh2 =
                    *TinySieve.offset((j >> 3 as libc::c_int + 2 as libc::c_int) as isize);
                *fresh2 = (*fresh2 as libc::c_long
                    | (1 as libc::c_long) << (j & 31 as libc::c_int as libc::c_uint))
                    as u_int32_t;
                j = (j as libc::c_uint).wrapping_add(t) as u_int32_t as u_int32_t;
            }
            sieve_large(t);
        }
        i = i.wrapping_add(1);
        i;
    }
    smallbase = ((1 as libc::c_ulong) << 16 as libc::c_int)
        .wrapping_add(3 as libc::c_int as libc::c_ulong) as u_int32_t;
    while (smallbase as libc::c_ulong)
        < (0xffffffff as libc::c_ulong).wrapping_sub((1 as libc::c_ulong) << 16 as libc::c_int)
    {
        i = 0 as libc::c_int as u_int32_t;
        while i < tinybits {
            if !(*TinySieve.offset((i >> 3 as libc::c_int + 2 as libc::c_int) as isize)
                as libc::c_long
                & (1 as libc::c_long) << (i & 31 as libc::c_int as libc::c_uint)
                != 0)
            {
                t = (2 as libc::c_int as libc::c_uint)
                    .wrapping_mul(i)
                    .wrapping_add(3 as libc::c_int as libc::c_uint);
                r = smallbase.wrapping_rem(t);
                if r == 0 as libc::c_int as libc::c_uint {
                    s = 0 as libc::c_int as u_int32_t;
                } else {
                    s = t.wrapping_sub(r);
                }
                if s & 1 as libc::c_int as libc::c_uint != 0 {
                    s = (s as libc::c_uint).wrapping_add(t) as u_int32_t as u_int32_t;
                }
                s = (s as libc::c_uint).wrapping_div(2 as libc::c_int as libc::c_uint) as u_int32_t
                    as u_int32_t;
                while s < smallbits {
                    let ref mut fresh3 =
                        *SmallSieve.offset((s >> 3 as libc::c_int + 2 as libc::c_int) as isize);
                    *fresh3 = (*fresh3 as libc::c_long
                        | (1 as libc::c_long) << (s & 31 as libc::c_int as libc::c_uint))
                        as u_int32_t;
                    s = (s as libc::c_uint).wrapping_add(t) as u_int32_t as u_int32_t;
                }
            }
            i = i.wrapping_add(1);
            i;
        }
        i = 0 as libc::c_int as u_int32_t;
        while i < smallbits {
            if !(*SmallSieve.offset((i >> 3 as libc::c_int + 2 as libc::c_int) as isize)
                as libc::c_long
                & (1 as libc::c_long) << (i & 31 as libc::c_int as libc::c_uint)
                != 0)
            {
                sieve_large(
                    (2 as libc::c_int as libc::c_uint)
                        .wrapping_mul(i)
                        .wrapping_add(smallbase),
                );
            }
            i = i.wrapping_add(1);
            i;
        }
        memset(
            SmallSieve as *mut libc::c_void,
            0 as libc::c_int,
            (smallwords << 2 as libc::c_int) as size_t,
        );
        smallbase = (smallbase as libc::c_ulong)
            .wrapping_add((1 as libc::c_ulong) << 16 as libc::c_int)
            as u_int32_t as u_int32_t;
    }
    time(&mut time_stop);
    sshlog(
        b"moduli.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0")).as_ptr(),
        418 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"%.24s Sieved with %u small primes in %lld seconds\0" as *const u8 as *const libc::c_char,
        ctime(&mut time_stop),
        largetries,
        (time_stop - time_start) as libc::c_longlong,
    );
    r = 0 as libc::c_int as u_int32_t;
    j = r;
    while j < largebits {
        if !(*LargeSieve.offset((j >> 3 as libc::c_int + 2 as libc::c_int) as isize)
            as libc::c_long
            & (1 as libc::c_long) << (j & 31 as libc::c_int as libc::c_uint)
            != 0)
        {
            sshlog(
                b"moduli.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0"))
                    .as_ptr(),
                424 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"test q = largebase+%u\0" as *const u8 as *const libc::c_char,
                (2 as libc::c_int as libc::c_uint).wrapping_mul(j),
            );
            if BN_set_word(
                q,
                (2 as libc::c_int as libc::c_uint).wrapping_mul(j) as libc::c_ulong,
            ) == 0 as libc::c_int
            {
                sshfatal(
                    b"moduli.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"gen_candidates\0",
                    ))
                    .as_ptr(),
                    426 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"BN_set_word failed\0" as *const u8 as *const libc::c_char,
                );
            }
            if BN_add(q, q, largebase) == 0 as libc::c_int {
                sshfatal(
                    b"moduli.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"gen_candidates\0",
                    ))
                    .as_ptr(),
                    428 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"BN_add failed\0" as *const u8 as *const libc::c_char,
                );
            }
            if qfileout(
                out,
                4 as libc::c_int as u_int32_t,
                0x2 as libc::c_int as u_int32_t,
                largetries,
                power.wrapping_sub(1 as libc::c_int as libc::c_uint),
                0 as libc::c_int as u_int32_t,
                q,
            ) == -(1 as libc::c_int)
            {
                ret = -(1 as libc::c_int);
                break;
            } else {
                r = r.wrapping_add(1);
                r;
            }
        }
        j = j.wrapping_add(1);
        j;
    }
    time(&mut time_stop);
    free(LargeSieve as *mut libc::c_void);
    free(SmallSieve as *mut libc::c_void);
    free(TinySieve as *mut libc::c_void);
    sshlog(
        b"moduli.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"gen_candidates\0")).as_ptr(),
        445 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"%.24s Found %u candidates\0" as *const u8 as *const libc::c_char,
        ctime(&mut time_stop),
        r,
    );
    return ret;
}
unsafe extern "C" fn write_checkpoint(mut cpfile: *mut libc::c_char, mut lineno: u_int32_t) {
    let mut fp: *mut FILE = 0 as *mut FILE;
    let mut tmp: [libc::c_char; 4096] = [0; 4096];
    let mut r: libc::c_int = 0;
    let mut writeok: libc::c_int = 0;
    let mut closeok: libc::c_int = 0;
    r = snprintf(
        tmp.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
        b"%s.XXXXXXXXXX\0" as *const u8 as *const libc::c_char,
        cpfile,
    );
    if r < 0 as libc::c_int || r >= 4096 as libc::c_int {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"write_checkpoint\0"))
                .as_ptr(),
            459 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"write_checkpoint: temp pathname too long\0" as *const u8 as *const libc::c_char,
        );
        return;
    }
    r = _ssh_mkstemp(tmp.as_mut_ptr());
    if r == -(1 as libc::c_int) {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"write_checkpoint\0"))
                .as_ptr(),
            463 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"mkstemp(%s): %s\0" as *const u8 as *const libc::c_char,
            tmp.as_mut_ptr(),
            strerror(*__errno_location()),
        );
        return;
    }
    fp = fdopen(r, b"w\0" as *const u8 as *const libc::c_char);
    if fp.is_null() {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"write_checkpoint\0"))
                .as_ptr(),
            467 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"write_checkpoint: fdopen: %s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        unlink(tmp.as_mut_ptr());
        close(r);
        return;
    }
    writeok = (fprintf(
        fp,
        b"%lu\n\0" as *const u8 as *const libc::c_char,
        lineno as libc::c_ulong,
    ) > 0 as libc::c_int) as libc::c_int;
    closeok = (fclose(fp) == 0 as libc::c_int) as libc::c_int;
    if writeok != 0 && closeok != 0 && rename(tmp.as_mut_ptr(), cpfile) == 0 as libc::c_int {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"write_checkpoint\0"))
                .as_ptr(),
            476 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"wrote checkpoint line %lu to '%s'\0" as *const u8 as *const libc::c_char,
            lineno as libc::c_ulong,
            cpfile,
        );
    } else {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"write_checkpoint\0"))
                .as_ptr(),
            479 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"failed to write to checkpoint file '%s': %s\0" as *const u8 as *const libc::c_char,
            cpfile,
            strerror(*__errno_location()),
        );
        unlink(tmp.as_mut_ptr());
    };
}
unsafe extern "C" fn read_checkpoint(mut cpfile: *mut libc::c_char) -> libc::c_ulong {
    let mut fp: *mut FILE = 0 as *mut FILE;
    let mut lineno: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
    fp = fopen(cpfile, b"r\0" as *const u8 as *const libc::c_char);
    if fp.is_null() {
        return 0 as libc::c_int as libc::c_ulong;
    }
    if fscanf(
        fp,
        b"%lu\n\0" as *const u8 as *const libc::c_char,
        &mut lineno as *mut libc::c_ulong,
    ) < 1 as libc::c_int
    {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"read_checkpoint\0"))
                .as_ptr(),
            493 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Failed to load checkpoint from '%s'\0" as *const u8 as *const libc::c_char,
            cpfile,
        );
    } else {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"read_checkpoint\0"))
                .as_ptr(),
            495 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Loaded checkpoint from '%s' line %lu\0" as *const u8 as *const libc::c_char,
            cpfile,
            lineno,
        );
    }
    fclose(fp);
    return lineno;
}
unsafe extern "C" fn count_lines(mut f: *mut FILE) -> libc::c_ulong {
    let mut count: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
    let mut lp: [libc::c_char; 8293] = [0; 8293];
    if fseek(f, 0 as libc::c_int as libc::c_long, 0 as libc::c_int) != 0 as libc::c_int {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"count_lines\0")).as_ptr(),
            507 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"input file is not seekable\0" as *const u8 as *const libc::c_char,
        );
        return (9223372036854775807 as libc::c_long as libc::c_ulong)
            .wrapping_mul(2 as libc::c_ulong)
            .wrapping_add(1 as libc::c_ulong);
    }
    while !(fgets(
        lp.as_mut_ptr(),
        100 as libc::c_int + 8192 as libc::c_int + 1 as libc::c_int,
        f,
    ))
    .is_null()
    {
        count = count.wrapping_add(1);
        count;
    }
    rewind(f);
    sshlog(
        b"moduli.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"count_lines\0")).as_ptr(),
        513 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"input file has %lu lines\0" as *const u8 as *const libc::c_char,
        count,
    );
    return count;
}
unsafe extern "C" fn fmt_time(mut seconds: time_t) -> *mut libc::c_char {
    let mut day: libc::c_int = 0;
    let mut hr: libc::c_int = 0;
    let mut min: libc::c_int = 0;
    static mut buf: [libc::c_char; 128] = [0; 128];
    min = (seconds / 60 as libc::c_int as libc::c_long % 60 as libc::c_int as libc::c_long)
        as libc::c_int;
    hr = (seconds / 60 as libc::c_int as libc::c_long / 60 as libc::c_int as libc::c_long
        % 24 as libc::c_int as libc::c_long) as libc::c_int;
    day = (seconds
        / 60 as libc::c_int as libc::c_long
        / 60 as libc::c_int as libc::c_long
        / 24 as libc::c_int as libc::c_long) as libc::c_int;
    if day > 0 as libc::c_int {
        snprintf(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            b"%dd %d:%02d\0" as *const u8 as *const libc::c_char,
            day,
            hr,
            min,
        );
    } else {
        snprintf(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            b"%d:%02d\0" as *const u8 as *const libc::c_char,
            hr,
            min,
        );
    }
    return buf.as_mut_ptr();
}
unsafe extern "C" fn print_progress(
    mut start_lineno: libc::c_ulong,
    mut current_lineno: libc::c_ulong,
    mut end_lineno: libc::c_ulong,
) {
    static mut time_start: time_t = 0;
    static mut time_prev: time_t = 0;
    let mut time_now: time_t = 0;
    let mut elapsed: time_t = 0;
    let mut num_to_process: libc::c_ulong = 0;
    let mut processed: libc::c_ulong = 0;
    let mut remaining: libc::c_ulong = 0;
    let mut percent: libc::c_ulong = 0;
    let mut eta: libc::c_ulong = 0;
    let mut time_per_line: libc::c_double = 0.;
    let mut eta_str: *mut libc::c_char = 0 as *mut libc::c_char;
    time_now = monotime();
    if time_start == 0 as libc::c_int as libc::c_long {
        time_prev = time_now;
        time_start = time_prev;
        return;
    }
    if time_now - time_prev < (5 as libc::c_int * 60 as libc::c_int) as libc::c_long {
        return;
    }
    time_prev = time_now;
    elapsed = time_now - time_start;
    processed = current_lineno.wrapping_sub(start_lineno);
    remaining = end_lineno.wrapping_sub(current_lineno);
    num_to_process = end_lineno.wrapping_sub(start_lineno);
    time_per_line = elapsed as libc::c_double / processed as libc::c_double;
    time(&mut time_now);
    if end_lineno
        == (9223372036854775807 as libc::c_long as libc::c_ulong)
            .wrapping_mul(2 as libc::c_ulong)
            .wrapping_add(1 as libc::c_ulong)
    {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"print_progress\0"))
                .as_ptr(),
            561 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%.24s processed %lu in %s\0" as *const u8 as *const libc::c_char,
            ctime(&mut time_now),
            processed,
            fmt_time(elapsed),
        );
        return;
    }
    percent = (100 as libc::c_int as libc::c_ulong)
        .wrapping_mul(processed)
        .wrapping_div(num_to_process);
    eta = (time_per_line * remaining as libc::c_double) as libc::c_ulong;
    eta_str = xstrdup(fmt_time(eta as time_t));
    sshlog(
        b"moduli.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"print_progress\0")).as_ptr(),
        569 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"%.24s processed %lu of %lu (%lu%%) in %s, ETA %s\0" as *const u8 as *const libc::c_char,
        ctime(&mut time_now),
        processed,
        num_to_process,
        percent,
        fmt_time(elapsed),
        eta_str,
    );
    free(eta_str as *mut libc::c_void);
}
pub unsafe extern "C" fn prime_test(
    mut in_0: *mut FILE,
    mut out: *mut FILE,
    mut trials: u_int32_t,
    mut generator_wanted: u_int32_t,
    mut checkpoint_file: *mut libc::c_char,
    mut start_lineno: libc::c_ulong,
    mut num_lines: libc::c_ulong,
) -> libc::c_int {
    let mut q: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut p: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut a: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut lp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut count_in: u_int32_t = 0 as libc::c_int as u_int32_t;
    let mut count_out: u_int32_t = 0 as libc::c_int as u_int32_t;
    let mut count_possible: u_int32_t = 0 as libc::c_int as u_int32_t;
    let mut generator_known: u_int32_t = 0;
    let mut in_tests: u_int32_t = 0;
    let mut in_tries: u_int32_t = 0;
    let mut in_type: u_int32_t = 0;
    let mut in_size: u_int32_t = 0;
    let mut last_processed: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
    let mut end_lineno: libc::c_ulong = 0;
    let mut time_start: time_t = 0;
    let mut time_stop: time_t = 0;
    let mut res: libc::c_int = 0;
    let mut is_prime: libc::c_int = 0;
    if trials < 4 as libc::c_int as libc::c_uint {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"prime_test\0")).as_ptr(),
            592 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Minimum primality trials is %d\0" as *const u8 as *const libc::c_char,
            4 as libc::c_int,
        );
        return -(1 as libc::c_int);
    }
    if num_lines == 0 as libc::c_int as libc::c_ulong {
        end_lineno = count_lines(in_0);
    } else {
        end_lineno = start_lineno.wrapping_add(num_lines);
    }
    time(&mut time_start);
    p = BN_new();
    if p.is_null() {
        sshfatal(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"prime_test\0")).as_ptr(),
            604 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"BN_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    q = BN_new();
    if q.is_null() {
        sshfatal(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"prime_test\0")).as_ptr(),
            606 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"BN_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    sshlog(
        b"moduli.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"prime_test\0")).as_ptr(),
        609 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"%.24s Final %u Miller-Rabin trials (%x generator)\0" as *const u8 as *const libc::c_char,
        ctime(&mut time_start),
        trials,
        generator_wanted,
    );
    if !checkpoint_file.is_null() {
        last_processed = read_checkpoint(checkpoint_file);
    }
    start_lineno = if last_processed > start_lineno {
        last_processed
    } else {
        start_lineno
    };
    last_processed = start_lineno;
    if end_lineno
        == (9223372036854775807 as libc::c_long as libc::c_ulong)
            .wrapping_mul(2 as libc::c_ulong)
            .wrapping_add(1 as libc::c_ulong)
    {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"prime_test\0")).as_ptr(),
            615 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"process from line %lu from pipe\0" as *const u8 as *const libc::c_char,
            last_processed,
        );
    } else {
        sshlog(
            b"moduli.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"prime_test\0")).as_ptr(),
            618 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"process from line %lu to line %lu\0" as *const u8 as *const libc::c_char,
            last_processed,
            end_lineno,
        );
    }
    res = 0 as libc::c_int;
    lp = xmalloc((100 as libc::c_int + 8192 as libc::c_int + 1 as libc::c_int) as size_t)
        as *mut libc::c_char;
    while !(fgets(
        lp,
        100 as libc::c_int + 8192 as libc::c_int + 1 as libc::c_int,
        in_0,
    ))
    .is_null()
        && (count_in as libc::c_ulong) < end_lineno
    {
        count_in = count_in.wrapping_add(1);
        count_in;
        if count_in as libc::c_ulong <= last_processed {
            sshlog(
                b"moduli.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"prime_test\0"))
                    .as_ptr(),
                626 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"skipping line %u, before checkpoint or specified start line\0" as *const u8
                    as *const libc::c_char,
                count_in,
            );
        } else {
            if !checkpoint_file.is_null() {
                write_checkpoint(checkpoint_file, count_in);
            }
            print_progress(start_lineno, count_in as libc::c_ulong, end_lineno);
            if strlen(lp) < 14 as libc::c_int as libc::c_ulong
                || *lp as libc::c_int == '!' as i32
                || *lp as libc::c_int == '#' as i32
            {
                sshlog(
                    b"moduli.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"prime_test\0"))
                        .as_ptr(),
                    633 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"%10u: comment or short line\0" as *const u8 as *const libc::c_char,
                    count_in,
                );
            } else {
                cp = &mut *lp.offset(14 as libc::c_int as isize) as *mut libc::c_char;
                in_type = strtoul(cp, &mut cp, 10 as libc::c_int) as u_int32_t;
                in_tests = strtoul(cp, &mut cp, 10 as libc::c_int) as u_int32_t;
                if in_tests & 0x1 as libc::c_int as libc::c_uint != 0 {
                    sshlog(
                        b"moduli.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                            b"prime_test\0",
                        ))
                        .as_ptr(),
                        648 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        0 as *const libc::c_char,
                        b"%10u: known composite\0" as *const u8 as *const libc::c_char,
                        count_in,
                    );
                } else {
                    in_tries = strtoul(cp, &mut cp, 10 as libc::c_int) as u_int32_t;
                    in_size = strtoul(cp, &mut cp, 10 as libc::c_int) as u_int32_t;
                    generator_known = strtoul(cp, &mut cp, 16 as libc::c_int) as u_int32_t;
                    cp = cp.offset(strspn(cp, b" \0" as *const u8 as *const libc::c_char) as isize);
                    match in_type {
                        4 => {
                            sshlog(
                                b"moduli.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                    b"prime_test\0",
                                ))
                                .as_ptr(),
                                667 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"%10u: (%u) Sophie-Germain\0" as *const u8 as *const libc::c_char,
                                count_in,
                                in_type,
                            );
                            a = q;
                            if BN_hex2bn(&mut a, cp) == 0 as libc::c_int {
                                sshfatal(
                                    b"moduli.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                        b"prime_test\0",
                                    ))
                                    .as_ptr(),
                                    670 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    0 as *const libc::c_char,
                                    b"BN_hex2bn failed\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            if BN_lshift(p, q, 1 as libc::c_int) == 0 as libc::c_int {
                                sshfatal(
                                    b"moduli.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                        b"prime_test\0",
                                    ))
                                    .as_ptr(),
                                    673 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    0 as *const libc::c_char,
                                    b"BN_lshift failed\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            if BN_add_word(p, 1 as libc::c_int as libc::c_ulong) == 0 as libc::c_int
                            {
                                sshfatal(
                                    b"moduli.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                        b"prime_test\0",
                                    ))
                                    .as_ptr(),
                                    675 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    0 as *const libc::c_char,
                                    b"BN_add_word failed\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            in_size = (in_size as libc::c_uint)
                                .wrapping_add(1 as libc::c_int as libc::c_uint)
                                as u_int32_t as u_int32_t;
                            generator_known = 0 as libc::c_int as u_int32_t;
                        }
                        1 | 2 | 3 | 5 | 0 => {
                            sshlog(
                                b"moduli.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                    b"prime_test\0",
                                ))
                                .as_ptr(),
                                684 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"%10u: (%u)\0" as *const u8 as *const libc::c_char,
                                count_in,
                                in_type,
                            );
                            a = p;
                            if BN_hex2bn(&mut a, cp) == 0 as libc::c_int {
                                sshfatal(
                                    b"moduli.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                        b"prime_test\0",
                                    ))
                                    .as_ptr(),
                                    687 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    0 as *const libc::c_char,
                                    b"BN_hex2bn failed\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            if BN_rshift(q, p, 1 as libc::c_int) == 0 as libc::c_int {
                                sshfatal(
                                    b"moduli.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                        b"prime_test\0",
                                    ))
                                    .as_ptr(),
                                    690 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    0 as *const libc::c_char,
                                    b"BN_rshift failed\0" as *const u8 as *const libc::c_char,
                                );
                            }
                        }
                        _ => {
                            sshlog(
                                b"moduli.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                    b"prime_test\0",
                                ))
                                .as_ptr(),
                                693 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"Unknown prime type\0" as *const u8 as *const libc::c_char,
                            );
                        }
                    }
                    if BN_num_bits(p) as u_int32_t
                        != in_size.wrapping_add(1 as libc::c_int as libc::c_uint)
                    {
                        sshlog(
                            b"moduli.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                b"prime_test\0",
                            ))
                            .as_ptr(),
                            702 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"%10u: bit size %u mismatch\0" as *const u8 as *const libc::c_char,
                            count_in,
                            in_size,
                        );
                    } else if in_size < 511 as libc::c_int as libc::c_uint {
                        sshlog(
                            b"moduli.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                b"prime_test\0",
                            ))
                            .as_ptr(),
                            706 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"%10u: bit size %u too short\0" as *const u8 as *const libc::c_char,
                            count_in,
                            in_size,
                        );
                    } else {
                        if in_tests & 0x4 as libc::c_int as libc::c_uint != 0 {
                            in_tries = (in_tries as libc::c_uint).wrapping_add(trials) as u_int32_t
                                as u_int32_t;
                        } else {
                            in_tries = trials;
                        }
                        if generator_known == 0 as libc::c_int as libc::c_uint {
                            if BN_mod_word(p, 24 as libc::c_int as libc::c_ulong)
                                == 11 as libc::c_int as libc::c_ulong
                            {
                                generator_known = 2 as libc::c_int as u_int32_t;
                            } else {
                                let mut r: u_int32_t =
                                    BN_mod_word(p, 10 as libc::c_int as libc::c_ulong) as u_int32_t;
                                if r == 3 as libc::c_int as libc::c_uint
                                    || r == 7 as libc::c_int as libc::c_uint
                                {
                                    generator_known = 5 as libc::c_int as u_int32_t;
                                }
                            }
                        }
                        if generator_wanted > 0 as libc::c_int as libc::c_uint
                            && generator_wanted != generator_known
                        {
                            sshlog(
                                b"moduli.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                    b"prime_test\0",
                                ))
                                .as_ptr(),
                                734 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"%10u: generator %d != %d\0" as *const u8 as *const libc::c_char,
                                count_in,
                                generator_known,
                                generator_wanted,
                            );
                        } else if generator_known == 0 as libc::c_int as libc::c_uint {
                            sshlog(
                                b"moduli.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                    b"prime_test\0",
                                ))
                                .as_ptr(),
                                743 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"%10u: no known generator\0" as *const u8 as *const libc::c_char,
                                count_in,
                            );
                        } else {
                            count_possible = count_possible.wrapping_add(1);
                            count_possible;
                            is_prime = BN_is_prime_ex(
                                q,
                                1 as libc::c_int,
                                0 as *mut BN_CTX,
                                0 as *mut BN_GENCB,
                            );
                            if is_prime < 0 as libc::c_int {
                                sshfatal(
                                    b"moduli.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                        b"prime_test\0",
                                    ))
                                    .as_ptr(),
                                    758 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    0 as *const libc::c_char,
                                    b"BN_is_prime_ex failed\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            if is_prime == 0 as libc::c_int {
                                sshlog(
                                    b"moduli.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                        b"prime_test\0",
                                    ))
                                    .as_ptr(),
                                    761 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG1,
                                    0 as *const libc::c_char,
                                    b"%10u: q failed first possible prime test\0" as *const u8
                                        as *const libc::c_char,
                                    count_in,
                                );
                            } else {
                                is_prime = BN_is_prime_ex(
                                    p,
                                    trials as libc::c_int,
                                    0 as *mut BN_CTX,
                                    0 as *mut BN_GENCB,
                                );
                                if is_prime < 0 as libc::c_int {
                                    sshfatal(
                                        b"moduli.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                            b"prime_test\0",
                                        ))
                                        .as_ptr(),
                                        774 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_FATAL,
                                        0 as *const libc::c_char,
                                        b"BN_is_prime_ex failed\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                }
                                if is_prime == 0 as libc::c_int {
                                    sshlog(
                                        b"moduli.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                            b"prime_test\0",
                                        ))
                                        .as_ptr(),
                                        776 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG1,
                                        0 as *const libc::c_char,
                                        b"%10u: p is not prime\0" as *const u8
                                            as *const libc::c_char,
                                        count_in,
                                    );
                                } else {
                                    sshlog(
                                        b"moduli.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                            b"prime_test\0",
                                        ))
                                        .as_ptr(),
                                        779 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG1,
                                        0 as *const libc::c_char,
                                        b"%10u: p is almost certainly prime\0" as *const u8
                                            as *const libc::c_char,
                                        count_in,
                                    );
                                    is_prime = BN_is_prime_ex(
                                        q,
                                        trials.wrapping_sub(1 as libc::c_int as libc::c_uint)
                                            as libc::c_int,
                                        0 as *mut BN_CTX,
                                        0 as *mut BN_GENCB,
                                    );
                                    if is_prime < 0 as libc::c_int {
                                        sshfatal(
                                            b"moduli.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 11],
                                                &[libc::c_char; 11],
                                            >(
                                                b"prime_test\0"
                                            ))
                                            .as_ptr(),
                                            784 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_FATAL,
                                            0 as *const libc::c_char,
                                            b"BN_is_prime_ex failed\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                    }
                                    if is_prime == 0 as libc::c_int {
                                        sshlog(
                                            b"moduli.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 11],
                                                &[libc::c_char; 11],
                                            >(
                                                b"prime_test\0"
                                            ))
                                            .as_ptr(),
                                            786 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_DEBUG1,
                                            0 as *const libc::c_char,
                                            b"%10u: q is not prime\0" as *const u8
                                                as *const libc::c_char,
                                            count_in,
                                        );
                                    } else {
                                        sshlog(
                                            b"moduli.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 11],
                                                &[libc::c_char; 11],
                                            >(
                                                b"prime_test\0"
                                            ))
                                            .as_ptr(),
                                            789 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_DEBUG1,
                                            0 as *const libc::c_char,
                                            b"%10u: q is almost certainly prime\0" as *const u8
                                                as *const libc::c_char,
                                            count_in,
                                        );
                                        if qfileout(
                                            out,
                                            2 as libc::c_int as u_int32_t,
                                            in_tests | 0x4 as libc::c_int as libc::c_uint,
                                            in_tries,
                                            in_size,
                                            generator_known,
                                            p,
                                        ) != 0
                                        {
                                            res = -(1 as libc::c_int);
                                            break;
                                        } else {
                                            count_out = count_out.wrapping_add(1);
                                            count_out;
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
    time(&mut time_stop);
    free(lp as *mut libc::c_void);
    BN_free(p);
    BN_free(q);
    if !checkpoint_file.is_null() {
        unlink(checkpoint_file);
    }
    sshlog(
        b"moduli.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"prime_test\0")).as_ptr(),
        811 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"%.24s Found %u safe primes of %u candidates in %ld seconds\0" as *const u8
            as *const libc::c_char,
        ctime(&mut time_stop),
        count_out,
        count_possible,
        time_stop - time_start,
    );
    return res;
}
