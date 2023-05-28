use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn tcgetattr(__fd: libc::c_int, __termios_p: *mut termios) -> libc::c_int;
    fn tcsetattr(
        __fd: libc::c_int,
        __optional_actions: libc::c_int,
        __termios_p: *const termios,
    ) -> libc::c_int;
    static mut stdin: *mut libc::FILE;
    
    fn fileno(__stream: *mut libc::FILE) -> libc::c_int;
}
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type size_t = libc::c_ulong;
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

pub type _IO_lock_t = ();

static mut _saved_tio: termios = termios {
    c_iflag: 0,
    c_oflag: 0,
    c_cflag: 0,
    c_lflag: 0,
    c_line: 0,
    c_cc: [0; 32],
    c_ispeed: 0,
    c_ospeed: 0,
};
static mut _in_raw_mode: libc::c_int = 0 as libc::c_int;
pub unsafe extern "C" fn get_saved_tio() -> *mut termios {
    return if _in_raw_mode != 0 {
        &mut _saved_tio
    } else {
        0 as *mut termios
    };
}
pub unsafe extern "C" fn leave_raw_mode(mut quiet: libc::c_int) {
    if _in_raw_mode == 0 {
        return;
    }
    if tcsetattr(fileno(stdin), 1 as libc::c_int, &mut _saved_tio) == -(1 as libc::c_int) {
        if quiet == 0 {
            libc::perror(b"tcsetattr\0" as *const u8 as *const libc::c_char);
        }
    } else {
        _in_raw_mode = 0 as libc::c_int;
    };
}
pub unsafe extern "C" fn enter_raw_mode(mut quiet: libc::c_int) {
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
    if tcgetattr(fileno(stdin), &mut tio) == -(1 as libc::c_int) {
        if quiet == 0 {
            libc::perror(b"tcgetattr\0" as *const u8 as *const libc::c_char);
        }
        return;
    }
    _saved_tio = tio;
    tio.c_iflag |= 0o4 as libc::c_int as libc::c_uint;
    tio.c_iflag &= !(0o40 as libc::c_int
        | 0o100 as libc::c_int
        | 0o200 as libc::c_int
        | 0o400 as libc::c_int
        | 0o2000 as libc::c_int
        | 0o4000 as libc::c_int
        | 0o10000 as libc::c_int) as libc::c_uint;
    tio.c_iflag &= !(0o1000 as libc::c_int) as libc::c_uint;
    tio.c_lflag &= !(0o1 as libc::c_int
        | 0o2 as libc::c_int
        | 0o10 as libc::c_int
        | 0o20 as libc::c_int
        | 0o40 as libc::c_int
        | 0o100 as libc::c_int) as libc::c_uint;
    tio.c_lflag &= !(0o100000 as libc::c_int) as libc::c_uint;
    tio.c_oflag &= !(0o1 as libc::c_int) as libc::c_uint;
    tio.c_cc[6 as libc::c_int as usize] = 1 as libc::c_int as cc_t;
    tio.c_cc[5 as libc::c_int as usize] = 0 as libc::c_int as cc_t;
    if tcsetattr(fileno(stdin), 1 as libc::c_int, &mut tio) == -(1 as libc::c_int) {
        if quiet == 0 {
            libc::perror(b"tcsetattr\0" as *const u8 as *const libc::c_char);
        }
    } else {
        _in_raw_mode = 1 as libc::c_int;
    };
}
