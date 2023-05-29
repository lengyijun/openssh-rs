use ::libc;
extern "C" {
    pub type ssh_channels;
    pub type sshkey;
    pub type kex;
    pub type session_state;

    fn cfgetospeed(__termios_p: *const termios) -> speed_t;
    fn cfgetispeed(__termios_p: *const termios) -> speed_t;
    fn cfsetospeed(__termios_p: *mut termios, __speed: speed_t) -> libc::c_int;
    fn cfsetispeed(__termios_p: *mut termios, __speed: speed_t) -> libc::c_int;
    fn tcgetattr(__fd: libc::c_int, __termios_p: *mut termios) -> libc::c_int;
    fn tcsetattr(
        __fd: libc::c_int,
        __optional_actions: libc::c_int,
        __termios_p: *const termios,
    ) -> libc::c_int;

    fn sshpkt_get_string_direct(
        ssh: *mut ssh,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshpkt_put_stringb(ssh: *mut ssh, v: *const crate::sshbuf::sshbuf) -> libc::c_int;

    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
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

}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint32_t = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type cc_t = libc::c_uchar;
pub type speed_t = libc::c_uint;
pub type tcflag_t = libc::c_uint;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; 32],
    pub c_ispeed: speed_t,
    pub c_ospeed: speed_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh {
    pub state: *mut session_state,
    pub kex: *mut kex,
    pub remote_ipaddr: *mut libc::c_char,
    pub remote_port: libc::c_int,
    pub local_ipaddr: *mut libc::c_char,
    pub local_port: libc::c_int,
    pub rdomain_in: *mut libc::c_char,
    pub log_preamble: *mut libc::c_char,
    pub dispatch: [Option<dispatch_fn>; 255],
    pub dispatch_skip_packets: libc::c_int,
    pub compat: libc::c_int,
    pub private_keys: C2RustUnnamed_1,
    pub public_keys: C2RustUnnamed,
    pub authctxt: *mut libc::c_void,
    pub chanctxt: *mut ssh_channels,
    pub app_data: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct key_entry {
    pub next: C2RustUnnamed_0,
    pub key: *mut sshkey,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub tqe_next: *mut key_entry,
    pub tqe_prev: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
pub type dispatch_fn = unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int;
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
unsafe extern "C" fn speed_to_baud(mut speed: speed_t) -> libc::c_int {
    match speed {
        0 => return 0 as libc::c_int,
        1 => return 50 as libc::c_int,
        2 => return 75 as libc::c_int,
        3 => return 110 as libc::c_int,
        4 => return 134 as libc::c_int,
        5 => return 150 as libc::c_int,
        6 => return 200 as libc::c_int,
        7 => return 300 as libc::c_int,
        8 => return 600 as libc::c_int,
        9 => return 1200 as libc::c_int,
        10 => return 1800 as libc::c_int,
        11 => return 2400 as libc::c_int,
        12 => return 4800 as libc::c_int,
        13 => return 9600 as libc::c_int,
        14 => return 19200 as libc::c_int,
        15 => return 38400 as libc::c_int,
        4097 => return 57600 as libc::c_int,
        4098 => return 115200 as libc::c_int,
        4099 => return 230400 as libc::c_int,
        _ => return 9600 as libc::c_int,
    };
}
unsafe extern "C" fn baud_to_speed(mut baud: libc::c_int) -> speed_t {
    match baud {
        0 => return 0 as libc::c_int as speed_t,
        50 => return 0o1 as libc::c_int as speed_t,
        75 => return 0o2 as libc::c_int as speed_t,
        110 => return 0o3 as libc::c_int as speed_t,
        134 => return 0o4 as libc::c_int as speed_t,
        150 => return 0o5 as libc::c_int as speed_t,
        200 => return 0o6 as libc::c_int as speed_t,
        300 => return 0o7 as libc::c_int as speed_t,
        600 => return 0o10 as libc::c_int as speed_t,
        1200 => return 0o11 as libc::c_int as speed_t,
        1800 => return 0o12 as libc::c_int as speed_t,
        2400 => return 0o13 as libc::c_int as speed_t,
        4800 => return 0o14 as libc::c_int as speed_t,
        9600 => return 0o15 as libc::c_int as speed_t,
        19200 => return 0o16 as libc::c_int as speed_t,
        38400 => return 0o17 as libc::c_int as speed_t,
        57600 => return 0o10001 as libc::c_int as speed_t,
        115200 => return 0o10002 as libc::c_int as speed_t,
        230400 => return 0o10003 as libc::c_int as speed_t,
        _ => return 0o15 as libc::c_int as speed_t,
    };
}
unsafe extern "C" fn special_char_encode(mut c: cc_t) -> u_int {
    if c as libc::c_int == '\0' as i32 {
        return 255 as libc::c_int as u_int;
    }
    return c as u_int;
}
unsafe extern "C" fn special_char_decode(mut c: u_int) -> cc_t {
    if c == 255 as libc::c_int as libc::c_uint {
        return '\0' as i32 as cc_t;
    }
    return c as cc_t;
}
pub unsafe extern "C" fn ssh_tty_make_modes(
    mut ssh: *mut ssh,
    mut fd: libc::c_int,
    mut tiop: *mut termios,
) {
    let mut current_block: u64;
    let mut tio: termios = termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 32],
        c_ispeed: 0,
        c_ospeed: 0,
    };
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    let mut ibaud: libc::c_int = 0;
    let mut obaud: libc::c_int = 0;
    buf = crate::sshbuf::sshbuf_new();
    if buf.is_null() {
        sshfatal(
            b"ttymodes.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"ssh_tty_make_modes\0"))
                .as_ptr(),
            286 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    if tiop.is_null() {
        if fd == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"ttymodes.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"ssh_tty_make_modes\0",
                ))
                .as_ptr(),
                290 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"no fd or tio\0" as *const u8 as *const libc::c_char,
            );
            current_block = 10500593165445915707;
        } else if tcgetattr(fd, &mut tio) == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"ttymodes.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"ssh_tty_make_modes\0",
                ))
                .as_ptr(),
                294 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"tcgetattr: %.100s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
            current_block = 10500593165445915707;
        } else {
            current_block = 8515828400728868193;
        }
    } else {
        tio = *tiop;
        current_block = 8515828400728868193;
    }
    match current_block {
        8515828400728868193 => {
            obaud = speed_to_baud(cfgetospeed(&mut tio));
            ibaud = speed_to_baud(cfgetispeed(&mut tio));
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 129 as libc::c_int as u_char);
            if r != 0 as libc::c_int
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(buf, obaud as u_int32_t);
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u8(
                        buf,
                        128 as libc::c_int as u_char,
                    );
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(buf, ibaud as u_int32_t);
                    r != 0 as libc::c_int
                }
            {
                sshfatal(
                    b"ttymodes.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    307 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 1 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[0 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    61 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VINTR\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 2 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[1 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    62 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VQUIT\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 3 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[2 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    63 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VERASE\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 4 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[3 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    65 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VKILL\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 5 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[4 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    67 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VEOF\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 6 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[11 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    69 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VEOL\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 7 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[16 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    72 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VEOL2\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 8 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[8 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    74 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VSTART\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 9 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[9 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    75 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VSTOP\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 10 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[10 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    77 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VSUSP\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 12 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[12 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    83 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VREPRINT\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 13 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[14 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    86 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VWERASE\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 14 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[15 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    89 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VLNEXT\0" as *const u8 as *const libc::c_char,
                );
            }
            r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 18 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    buf,
                    special_char_encode(tio.c_cc[13 as libc::c_int as usize]),
                );
                r != 0 as libc::c_int
            } {
                sshfatal(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    101 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose %s\0" as *const u8 as *const libc::c_char,
                    b"VDISCARD\0" as *const u8 as *const libc::c_char,
                );
            }
            if 30 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    105 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 30 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_iflag & 0o4 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        105 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"IGNPAR\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 31 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    106 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 31 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_iflag & 0o10 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        106 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"PARMRK\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 32 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    107 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 32 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_iflag & 0o20 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        107 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"INPCK\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 33 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    108 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 33 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_iflag & 0o40 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        108 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"ISTRIP\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 34 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    109 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 34 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_iflag & 0o100 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        109 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"INLCR\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 35 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    110 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 35 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_iflag & 0o200 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        110 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"IGNCR\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 36 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    111 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 36 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_iflag & 0o400 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        111 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"ICRNL\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 37 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    113 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 37 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_iflag & 0o1000 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        113 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"IUCLC\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 38 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    115 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 38 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_iflag & 0o2000 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        115 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"IXON\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 39 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    116 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 39 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_iflag & 0o4000 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        116 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"IXANY\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 40 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    117 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 40 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_iflag & 0o10000 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        117 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"IXOFF\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 41 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    119 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 41 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_iflag & 0o20000 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        119 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"IMAXBEL\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 42 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    122 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 42 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_iflag & 0o40000 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        122 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"IUTF8\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 50 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    125 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 50 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_lflag & 0o1 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        125 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"ISIG\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 51 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    126 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 51 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_lflag & 0o2 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        126 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"ICANON\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 52 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    128 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 52 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_lflag & 0o4 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        128 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"XCASE\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 53 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    130 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 53 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_lflag & 0o10 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        130 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"ECHO\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 54 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    131 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 54 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_lflag & 0o20 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        131 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"ECHOE\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 55 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    132 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 55 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_lflag & 0o40 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        132 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"ECHOK\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 56 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    133 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 56 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_lflag & 0o100 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        133 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"ECHONL\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 57 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    134 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 57 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_lflag & 0o200 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        134 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"NOFLSH\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 58 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    135 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 58 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_lflag & 0o400 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        135 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"TOSTOP\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 59 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    137 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 59 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_lflag & 0o100000 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        137 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"IEXTEN\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 60 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    140 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 60 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_lflag & 0o1000 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        140 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"ECHOCTL\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 61 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    143 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 61 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_lflag & 0o4000 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        143 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"ECHOKE\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 62 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    146 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 62 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_lflag & 0o40000 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        146 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"PENDIN\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 70 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    149 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 70 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_oflag & 0o1 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        149 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"OPOST\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 71 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    151 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 71 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_oflag & 0o2 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        151 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"OLCUC\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 72 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    154 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 72 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_oflag & 0o4 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        154 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"ONLCR\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 73 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    157 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 73 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_oflag & 0o10 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        157 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"OCRNL\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 74 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    160 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 74 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_oflag & 0o20 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        160 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"ONOCR\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 75 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    163 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 75 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_oflag & 0o40 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        163 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"ONLRET\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 90 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    166 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 90 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_cflag & 0o40 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        166 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"CS7\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 91 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    167 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 91 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_cflag & 0o60 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        167 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"CS8\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 92 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    168 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 92 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_cflag & 0o400 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        168 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"PARENB\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            if 93 as libc::c_int == 42 as libc::c_int && (*ssh).compat & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_tty_make_modes\0",
                    ))
                    .as_ptr(),
                    169 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"SSH_BUG_UTF8TTYMODE\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 93 as libc::c_int as u_char);
                if r != 0 as libc::c_int || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                        buf,
                        (tio.c_cflag & 0o1000 as libc::c_int as libc::c_uint
                            != 0 as libc::c_int as libc::c_uint)
                            as libc::c_int as u_int32_t,
                    );
                    r != 0 as libc::c_int
                } {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"ssh_tty_make_modes\0",
                        ))
                        .as_ptr(),
                        169 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"compose %s\0" as *const u8 as *const libc::c_char,
                        b"PARODD\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
        }
        _ => {}
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_u8(buf, 0 as libc::c_int as u_char);
    if r != 0 as libc::c_int || {
        r = sshpkt_put_stringb(ssh, buf);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"ttymodes.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"ssh_tty_make_modes\0"))
                .as_ptr(),
            334 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose end\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_free(buf);
}
pub unsafe extern "C" fn ssh_tty_parse_modes(mut ssh: *mut ssh, mut fd: libc::c_int) {
    let mut tio: termios = termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 32],
        c_ispeed: 0,
        c_ospeed: 0,
    };
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut data: *const u_char = 0 as *const u_char;
    let mut opcode: u_char = 0;
    let mut baud: u_int = 0;
    let mut u: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut failure: libc::c_int = 0 as libc::c_int;
    let mut len: size_t = 0;
    r = sshpkt_get_string_direct(ssh, &mut data, &mut len);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ttymodes.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"ssh_tty_parse_modes\0"))
                .as_ptr(),
            354 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if len == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    buf = crate::sshbuf::sshbuf_from(data as *const libc::c_void, len);
    if buf.is_null() {
        crate::log::sshlog(
            b"ttymodes.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"ssh_tty_parse_modes\0"))
                .as_ptr(),
            358 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"crate::sshbuf::sshbuf_from failed\0" as *const u8 as *const libc::c_char,
        );
        return;
    }
    if tcgetattr(fd, &mut tio) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"ttymodes.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"ssh_tty_parse_modes\0"))
                .as_ptr(),
            368 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"tcgetattr: %.100s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        failure = -(1 as libc::c_int);
    }
    while crate::sshbuf::sshbuf_len(buf) > 0 as libc::c_int as libc::c_ulong {
        r = crate::sshbuf_getput_basic::sshbuf_get_u8(buf, &mut opcode);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ttymodes.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"ssh_tty_parse_modes\0",
                ))
                .as_ptr(),
                374 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse opcode\0" as *const u8 as *const libc::c_char,
            );
        }
        match opcode as libc::c_int {
            0 => {
                break;
            }
            128 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut baud);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"ttymodes.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        381 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse ispeed\0" as *const u8 as *const libc::c_char,
                    );
                }
                if failure != -(1 as libc::c_int)
                    && cfsetispeed(&mut tio, baud_to_speed(baud as libc::c_int))
                        == -(1 as libc::c_int)
                {
                    crate::log::sshlog(
                        b"ttymodes.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        384 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"cfsetispeed failed for %d\0" as *const u8 as *const libc::c_char,
                        baud,
                    );
                }
            }
            129 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut baud);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"ttymodes.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        389 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse ospeed\0" as *const u8 as *const libc::c_char,
                    );
                }
                if failure != -(1 as libc::c_int)
                    && cfsetospeed(&mut tio, baud_to_speed(baud as libc::c_int))
                        == -(1 as libc::c_int)
                {
                    crate::log::sshlog(
                        b"ttymodes.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        392 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"cfsetospeed failed for %d\0" as *const u8 as *const libc::c_char,
                        baud,
                    );
                }
            }
            1 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        61 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VINTR\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[0 as libc::c_int as usize] = special_char_decode(u);
            }
            2 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        62 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VQUIT\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[1 as libc::c_int as usize] = special_char_decode(u);
            }
            3 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        63 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VERASE\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[2 as libc::c_int as usize] = special_char_decode(u);
            }
            4 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        65 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VKILL\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[3 as libc::c_int as usize] = special_char_decode(u);
            }
            5 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        67 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VEOF\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[4 as libc::c_int as usize] = special_char_decode(u);
            }
            6 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        69 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VEOL\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[11 as libc::c_int as usize] = special_char_decode(u);
            }
            7 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        72 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VEOL2\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[16 as libc::c_int as usize] = special_char_decode(u);
            }
            8 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        74 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VSTART\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[8 as libc::c_int as usize] = special_char_decode(u);
            }
            9 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        75 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VSTOP\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[9 as libc::c_int as usize] = special_char_decode(u);
            }
            10 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        77 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VSUSP\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[10 as libc::c_int as usize] = special_char_decode(u);
            }
            12 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        83 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VREPRINT\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[12 as libc::c_int as usize] = special_char_decode(u);
            }
            13 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        86 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VWERASE\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[14 as libc::c_int as usize] = special_char_decode(u);
            }
            14 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        89 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VLNEXT\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[15 as libc::c_int as usize] = special_char_decode(u);
            }
            18 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        101 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"VDISCARD\0" as *const u8 as *const libc::c_char,
                    );
                }
                tio.c_cc[13 as libc::c_int as usize] = special_char_decode(u);
            }
            30 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        105 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"IGNPAR\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_iflag |= 0o4 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_iflag &= !(0o4 as libc::c_int) as libc::c_uint;
                }
            }
            31 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        106 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"PARMRK\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_iflag |= 0o10 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_iflag &= !(0o10 as libc::c_int) as libc::c_uint;
                }
            }
            32 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        107 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"INPCK\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_iflag |= 0o20 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_iflag &= !(0o20 as libc::c_int) as libc::c_uint;
                }
            }
            33 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        108 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"ISTRIP\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_iflag |= 0o40 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_iflag &= !(0o40 as libc::c_int) as libc::c_uint;
                }
            }
            34 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        109 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"INLCR\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_iflag |= 0o100 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_iflag &= !(0o100 as libc::c_int) as libc::c_uint;
                }
            }
            35 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        110 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"IGNCR\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_iflag |= 0o200 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_iflag &= !(0o200 as libc::c_int) as libc::c_uint;
                }
            }
            36 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        111 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"ICRNL\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_iflag |= 0o400 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_iflag &= !(0o400 as libc::c_int) as libc::c_uint;
                }
            }
            37 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        113 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"IUCLC\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_iflag |= 0o1000 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_iflag &= !(0o1000 as libc::c_int) as libc::c_uint;
                }
            }
            38 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        115 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"IXON\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_iflag |= 0o2000 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_iflag &= !(0o2000 as libc::c_int) as libc::c_uint;
                }
            }
            39 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        116 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"IXANY\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_iflag |= 0o4000 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_iflag &= !(0o4000 as libc::c_int) as libc::c_uint;
                }
            }
            40 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        117 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"IXOFF\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_iflag |= 0o10000 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_iflag &= !(0o10000 as libc::c_int) as libc::c_uint;
                }
            }
            41 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        119 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"IMAXBEL\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_iflag |= 0o20000 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_iflag &= !(0o20000 as libc::c_int) as libc::c_uint;
                }
            }
            42 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        122 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"IUTF8\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_iflag |= 0o40000 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_iflag &= !(0o40000 as libc::c_int) as libc::c_uint;
                }
            }
            50 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        125 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"ISIG\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_lflag |= 0o1 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_lflag &= !(0o1 as libc::c_int) as libc::c_uint;
                }
            }
            51 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        126 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"ICANON\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_lflag |= 0o2 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_lflag &= !(0o2 as libc::c_int) as libc::c_uint;
                }
            }
            52 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        128 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"XCASE\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_lflag |= 0o4 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_lflag &= !(0o4 as libc::c_int) as libc::c_uint;
                }
            }
            53 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        130 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"ECHO\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_lflag |= 0o10 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_lflag &= !(0o10 as libc::c_int) as libc::c_uint;
                }
            }
            54 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        131 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"ECHOE\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_lflag |= 0o20 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_lflag &= !(0o20 as libc::c_int) as libc::c_uint;
                }
            }
            55 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        132 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"ECHOK\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_lflag |= 0o40 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_lflag &= !(0o40 as libc::c_int) as libc::c_uint;
                }
            }
            56 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        133 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"ECHONL\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_lflag |= 0o100 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_lflag &= !(0o100 as libc::c_int) as libc::c_uint;
                }
            }
            57 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        134 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"NOFLSH\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_lflag |= 0o200 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_lflag &= !(0o200 as libc::c_int) as libc::c_uint;
                }
            }
            58 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        135 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"TOSTOP\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_lflag |= 0o400 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_lflag &= !(0o400 as libc::c_int) as libc::c_uint;
                }
            }
            59 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        137 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"IEXTEN\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_lflag |= 0o100000 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_lflag &= !(0o100000 as libc::c_int) as libc::c_uint;
                }
            }
            60 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        140 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"ECHOCTL\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_lflag |= 0o1000 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_lflag &= !(0o1000 as libc::c_int) as libc::c_uint;
                }
            }
            61 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        143 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"ECHOKE\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_lflag |= 0o4000 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_lflag &= !(0o4000 as libc::c_int) as libc::c_uint;
                }
            }
            62 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        146 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"PENDIN\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_lflag |= 0o40000 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_lflag &= !(0o40000 as libc::c_int) as libc::c_uint;
                }
            }
            70 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        149 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"OPOST\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_oflag |= 0o1 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_oflag &= !(0o1 as libc::c_int) as libc::c_uint;
                }
            }
            71 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        151 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"OLCUC\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_oflag |= 0o2 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_oflag &= !(0o2 as libc::c_int) as libc::c_uint;
                }
            }
            72 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        154 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"ONLCR\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_oflag |= 0o4 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_oflag &= !(0o4 as libc::c_int) as libc::c_uint;
                }
            }
            73 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        157 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"OCRNL\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_oflag |= 0o10 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_oflag &= !(0o10 as libc::c_int) as libc::c_uint;
                }
            }
            74 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        160 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"ONOCR\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_oflag |= 0o20 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_oflag &= !(0o20 as libc::c_int) as libc::c_uint;
                }
            }
            75 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        163 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"ONLRET\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_oflag |= 0o40 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_oflag &= !(0o40 as libc::c_int) as libc::c_uint;
                }
            }
            90 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        166 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"CS7\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_cflag |= 0o40 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_cflag &= !(0o40 as libc::c_int) as libc::c_uint;
                }
            }
            91 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        167 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"CS8\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_cflag |= 0o60 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_cflag &= !(0o60 as libc::c_int) as libc::c_uint;
                }
            }
            92 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        168 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"PARENB\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_cflag |= 0o400 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_cflag &= !(0o400 as libc::c_int) as libc::c_uint;
                }
            }
            93 => {
                r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, &mut u);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"./ttymodes.h\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        169 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"parse %s\0" as *const u8 as *const libc::c_char,
                        b"PARODD\0" as *const u8 as *const libc::c_char,
                    );
                }
                if u != 0 {
                    tio.c_cflag |= 0o1000 as libc::c_int as libc::c_uint;
                } else {
                    tio.c_cflag &= !(0o1000 as libc::c_int) as libc::c_uint;
                }
            }
            _ => {
                crate::log::sshlog(
                    b"ttymodes.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"ssh_tty_parse_modes\0",
                    ))
                    .as_ptr(),
                    418 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"Ignoring unsupported tty mode opcode %d (0x%x)\0" as *const u8
                        as *const libc::c_char,
                    opcode as libc::c_int,
                    opcode as libc::c_int,
                );
                if opcode as libc::c_int > 0 as libc::c_int
                    && (opcode as libc::c_int) < 160 as libc::c_int
                {
                    r = crate::sshbuf_getput_basic::sshbuf_get_u32(buf, 0 as *mut u_int32_t);
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"ttymodes.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                b"ssh_tty_parse_modes\0",
                            ))
                            .as_ptr(),
                            428 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"parse arg\0" as *const u8 as *const libc::c_char,
                        );
                    }
                } else {
                    crate::log::sshlog(
                        b"ttymodes.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"ssh_tty_parse_modes\0",
                        ))
                        .as_ptr(),
                        431 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        0 as *const libc::c_char,
                        b"unknown opcode %d\0" as *const u8 as *const libc::c_char,
                        opcode as libc::c_int,
                    );
                    break;
                }
            }
        }
    }
    len = crate::sshbuf::sshbuf_len(buf);
    crate::sshbuf::sshbuf_free(buf);
    if len > 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ttymodes.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"ssh_tty_parse_modes\0"))
                .as_ptr(),
            441 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%zu bytes left\0" as *const u8 as *const libc::c_char,
            len,
        );
        return;
    }
    if failure == -(1 as libc::c_int) {
        return;
    }
    if tcsetattr(fd, 0 as libc::c_int, &mut tio) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"ttymodes.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"ssh_tty_parse_modes\0"))
                .as_ptr(),
            449 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Setting tty modes failed: %.100s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
}
