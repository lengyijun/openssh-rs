use ::libc;
use libc::close;
use libc::kill;
extern "C" {

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn tcgetattr(__fd: libc::c_int, __termios_p: *mut termios) -> libc::c_int;
    fn tcsetattr(
        __fd: libc::c_int,
        __optional_actions: libc::c_int,
        __termios_p: *const termios,
    ) -> libc::c_int;

    

    fn sigaction(
        __sig: libc::c_int,
        __act: *const sigaction,
        __oact: *mut sigaction,
    ) -> libc::c_int;
    fn sigemptyset(__set: *mut sigset_t) -> libc::c_int;
    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    fn __ctype_tolower_loc() -> *mut *const __int32_t;
    fn __ctype_toupper_loc() -> *mut *const __int32_t;

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
}
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uid_t = libc::c_uint;
pub type __pid_t = libc::c_int;
pub type __clock_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __sig_atomic_t = libc::c_int;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __sigset_t {
    pub __val: [libc::c_ulong; 16],
}
pub type sigset_t = __sigset_t;
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
pub type sig_atomic_t = __sig_atomic_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sigaction {
    pub __sigaction_handler: C2RustUnnamed,
    pub sa_mask: __sigset_t,
    pub sa_flags: libc::c_int,
    pub sa_restorer: Option<unsafe extern "C" fn() -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub sa_handler: __sighandler_t,
    pub sa_sigaction:
        Option<unsafe extern "C" fn(libc::c_int, *mut siginfo_t, *mut libc::c_void) -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct siginfo_t {
    pub si_signo: libc::c_int,
    pub si_errno: libc::c_int,
    pub si_code: libc::c_int,
    pub __pad0: libc::c_int,
    pub _sifields: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub _pad: [libc::c_int; 28],
    pub _kill: C2RustUnnamed_9,
    pub _timer: C2RustUnnamed_8,
    pub _rt: C2RustUnnamed_7,
    pub _sigchld: C2RustUnnamed_6,
    pub _sigfault: C2RustUnnamed_3,
    pub _sigpoll: C2RustUnnamed_2,
    pub _sigsys: C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub _call_addr: *mut libc::c_void,
    pub _syscall: libc::c_int,
    pub _arch: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub si_band: libc::c_long,
    pub si_fd: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_3 {
    pub si_addr: *mut libc::c_void,
    pub si_addr_lsb: libc::c_short,
    pub _bounds: C2RustUnnamed_4,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_4 {
    pub _addr_bnd: C2RustUnnamed_5,
    pub _pkey: __uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_5 {
    pub _lower: *mut libc::c_void,
    pub _upper: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_6 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
    pub si_status: libc::c_int,
    pub si_utime: __clock_t,
    pub si_stime: __clock_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_7 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
    pub si_sigval: __sigval_t,
}
pub type __sigval_t = sigval;
#[derive(Copy, Clone)]
#[repr(C)]
pub union sigval {
    pub sival_int: libc::c_int,
    pub sival_ptr: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_8 {
    pub si_tid: libc::c_int,
    pub si_overrun: libc::c_int,
    pub si_sigval: __sigval_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_9 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
}
pub type __sighandler_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
pub const _ISalpha: C2RustUnnamed_10 = 1024;
pub type C2RustUnnamed_10 = libc::c_uint;
pub const _ISalnum: C2RustUnnamed_10 = 8;
pub const _ISpunct: C2RustUnnamed_10 = 4;
pub const _IScntrl: C2RustUnnamed_10 = 2;
pub const _ISblank: C2RustUnnamed_10 = 1;
pub const _ISgraph: C2RustUnnamed_10 = 32768;
pub const _ISprint: C2RustUnnamed_10 = 16384;
pub const _ISspace: C2RustUnnamed_10 = 8192;
pub const _ISxdigit: C2RustUnnamed_10 = 4096;
pub const _ISdigit: C2RustUnnamed_10 = 2048;
pub const _ISlower: C2RustUnnamed_10 = 512;
pub const _ISupper: C2RustUnnamed_10 = 256;
#[inline]
unsafe extern "C" fn tolower(mut __c: libc::c_int) -> libc::c_int {
    return if __c >= -(128 as libc::c_int) && __c < 256 as libc::c_int {
        *(*__ctype_tolower_loc()).offset(__c as isize)
    } else {
        __c
    };
}
#[inline]
unsafe extern "C" fn toupper(mut __c: libc::c_int) -> libc::c_int {
    return if __c >= -(128 as libc::c_int) && __c < 256 as libc::c_int {
        *(*__ctype_toupper_loc()).offset(__c as isize)
    } else {
        __c
    };
}
static mut signo: [sig_atomic_t; 65] = [0; 65];
#[no_mangle]
pub unsafe extern "C" fn readpassphrase(
    mut prompt: *const libc::c_char,
    mut buf: *mut libc::c_char,
    mut bufsiz: size_t,
    mut flags: libc::c_int,
) -> *mut libc::c_char {
    let mut nr: ssize_t = 0;
    let mut input: libc::c_int = 0;
    let mut output: libc::c_int = 0;
    let mut save_errno: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut need_restart: libc::c_int = 0;
    let mut ch: libc::c_char = 0;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut end: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut term: termios = termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 32],
        c_ispeed: 0,
        c_ospeed: 0,
    };
    let mut oterm: termios = termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 32],
        c_ispeed: 0,
        c_ospeed: 0,
    };
    let mut sa: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed { sa_handler: None },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    let mut savealrm: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed { sa_handler: None },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    let mut saveint: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed { sa_handler: None },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    let mut savehup: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed { sa_handler: None },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    let mut savequit: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed { sa_handler: None },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    let mut saveterm: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed { sa_handler: None },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    let mut savetstp: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed { sa_handler: None },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    let mut savettin: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed { sa_handler: None },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    let mut savettou: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed { sa_handler: None },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    let mut savepipe: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed { sa_handler: None },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    if bufsiz == 0 as libc::c_int as libc::c_ulong {
        *libc::__errno_location() = 22 as libc::c_int;
        return 0 as *mut libc::c_char;
    }
    loop {
        i = 0 as libc::c_int;
        while i < 64 as libc::c_int + 1 as libc::c_int {
            ::core::ptr::write_volatile(
                &mut signo[i as usize] as *mut sig_atomic_t,
                0 as libc::c_int,
            );
            i += 1;
            i;
        }
        nr = -(1 as libc::c_int) as ssize_t;
        save_errno = 0 as libc::c_int;
        need_restart = 0 as libc::c_int;
        if flags & 0x20 as libc::c_int != 0 || {
            output = libc::open(
                b"/dev/tty\0" as *const u8 as *const libc::c_char,
                0o2 as libc::c_int,
            );
            input = output;
            input == -(1 as libc::c_int)
        } {
            if flags & 0x2 as libc::c_int != 0 {
                *libc::__errno_location() = 25 as libc::c_int;
                return 0 as *mut libc::c_char;
            }
            input = 0 as libc::c_int;
            output = 2 as libc::c_int;
        }
        if input != 0 as libc::c_int && tcgetattr(input, &mut oterm) == 0 as libc::c_int {
            memcpy(
                &mut term as *mut termios as *mut libc::c_void,
                &mut oterm as *mut termios as *const libc::c_void,
                ::core::mem::size_of::<termios>() as libc::c_ulong,
            );
            if flags & 0x1 as libc::c_int == 0 {
                term.c_lflag &= !(0o10 as libc::c_int | 0o100 as libc::c_int) as libc::c_uint;
            }
            tcsetattr(input, 2 as libc::c_int | 0 as libc::c_int, &mut term);
        } else {
            memset(
                &mut term as *mut termios as *mut libc::c_void,
                0 as libc::c_int,
                ::core::mem::size_of::<termios>() as libc::c_ulong,
            );
            term.c_lflag |= 0o10 as libc::c_int as libc::c_uint;
            memset(
                &mut oterm as *mut termios as *mut libc::c_void,
                0 as libc::c_int,
                ::core::mem::size_of::<termios>() as libc::c_ulong,
            );
            oterm.c_lflag |= 0o10 as libc::c_int as libc::c_uint;
        }
        sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0 as libc::c_int;
        sa.__sigaction_handler.sa_handler =
            Some(handler as unsafe extern "C" fn(libc::c_int) -> ());
        sigaction(14 as libc::c_int, &mut sa, &mut savealrm);
        sigaction(1 as libc::c_int, &mut sa, &mut savehup);
        sigaction(2 as libc::c_int, &mut sa, &mut saveint);
        sigaction(13 as libc::c_int, &mut sa, &mut savepipe);
        sigaction(3 as libc::c_int, &mut sa, &mut savequit);
        sigaction(15 as libc::c_int, &mut sa, &mut saveterm);
        sigaction(20 as libc::c_int, &mut sa, &mut savetstp);
        sigaction(21 as libc::c_int, &mut sa, &mut savettin);
        sigaction(22 as libc::c_int, &mut sa, &mut savettou);
        if flags & 0x20 as libc::c_int == 0 {
            write(output, prompt as *const libc::c_void, strlen(prompt));
        }
        end = buf
            .offset(bufsiz as isize)
            .offset(-(1 as libc::c_int as isize));
        p = buf;
        loop {
            nr = read(
                input,
                &mut ch as *mut libc::c_char as *mut libc::c_void,
                1 as libc::c_int as size_t,
            );
            if !(nr == 1 as libc::c_int as libc::c_long
                && ch as libc::c_int != '\n' as i32
                && ch as libc::c_int != '\r' as i32)
            {
                break;
            }
            if p < end {
                if flags & 0x10 as libc::c_int != 0 {
                    ch = (ch as libc::c_int & 0x7f as libc::c_int) as libc::c_char;
                }
                if *(*__ctype_b_loc()).offset(ch as libc::c_uchar as libc::c_int as isize)
                    as libc::c_int
                    & _ISalpha as libc::c_int as libc::c_ushort as libc::c_int
                    != 0
                {
                    if flags & 0x4 as libc::c_int != 0 {
                        ch = ({
                            let mut __res: libc::c_int = 0;
                            if ::core::mem::size_of::<libc::c_uchar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = ch as libc::c_uchar as libc::c_int;
                                    __res = if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_tolower_loc()).offset(__c as isize)
                                    };
                                } else {
                                    __res = tolower(ch as libc::c_uchar as libc::c_int);
                                }
                            } else {
                                __res = *(*__ctype_tolower_loc())
                                    .offset(ch as libc::c_uchar as libc::c_int as isize);
                            }
                            __res
                        }) as libc::c_char;
                    }
                    if flags & 0x8 as libc::c_int != 0 {
                        ch = ({
                            let mut __res: libc::c_int = 0;
                            if ::core::mem::size_of::<libc::c_uchar>() as libc::c_ulong
                                > 1 as libc::c_int as libc::c_ulong
                            {
                                if 0 != 0 {
                                    let mut __c: libc::c_int = ch as libc::c_uchar as libc::c_int;
                                    __res = if __c < -(128 as libc::c_int)
                                        || __c > 255 as libc::c_int
                                    {
                                        __c
                                    } else {
                                        *(*__ctype_toupper_loc()).offset(__c as isize)
                                    };
                                } else {
                                    __res = toupper(ch as libc::c_uchar as libc::c_int);
                                }
                            } else {
                                __res = *(*__ctype_toupper_loc())
                                    .offset(ch as libc::c_uchar as libc::c_int as isize);
                            }
                            __res
                        }) as libc::c_char;
                    }
                }
                let fresh0 = p;
                p = p.offset(1);
                *fresh0 = ch;
            }
        }
        *p = '\0' as i32 as libc::c_char;
        save_errno = *libc::__errno_location();
        if term.c_lflag & 0o10 as libc::c_int as libc::c_uint == 0 {
            write(
                output,
                b"\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                1 as libc::c_int as size_t,
            );
        }
        if memcmp(
            &mut term as *mut termios as *const libc::c_void,
            &mut oterm as *mut termios as *const libc::c_void,
            ::core::mem::size_of::<termios>() as libc::c_ulong,
        ) != 0 as libc::c_int
        {
            let sigttou: libc::c_int = signo[22 as libc::c_int as usize];
            while tcsetattr(input, 2 as libc::c_int | 0 as libc::c_int, &mut oterm)
                == -(1 as libc::c_int)
                && *libc::__errno_location() == 4 as libc::c_int
                && signo[22 as libc::c_int as usize] == 0
            {}
            ::core::ptr::write_volatile(
                &mut signo[22 as libc::c_int as usize] as *mut sig_atomic_t,
                sigttou,
            );
        }
        sigaction(14 as libc::c_int, &mut savealrm, 0 as *mut sigaction);
        sigaction(1 as libc::c_int, &mut savehup, 0 as *mut sigaction);
        sigaction(2 as libc::c_int, &mut saveint, 0 as *mut sigaction);
        sigaction(3 as libc::c_int, &mut savequit, 0 as *mut sigaction);
        sigaction(13 as libc::c_int, &mut savepipe, 0 as *mut sigaction);
        sigaction(15 as libc::c_int, &mut saveterm, 0 as *mut sigaction);
        sigaction(20 as libc::c_int, &mut savetstp, 0 as *mut sigaction);
        sigaction(21 as libc::c_int, &mut savettin, 0 as *mut sigaction);
        sigaction(22 as libc::c_int, &mut savettou, 0 as *mut sigaction);
        if input != 0 as libc::c_int {
            close(input);
        }
        i = 0 as libc::c_int;
        while i < 64 as libc::c_int + 1 as libc::c_int {
            if signo[i as usize] != 0 {
                kill(libc::getpid(), i);
                match i {
                    20 | 21 | 22 => {
                        need_restart = 1 as libc::c_int;
                    }
                    _ => {}
                }
            }
            i += 1;
            i;
        }
        if !(need_restart != 0) {
            break;
        }
    }
    if save_errno != 0 {
        *libc::__errno_location() = save_errno;
    }
    return if nr == -(1 as libc::c_int) as libc::c_long {
        0 as *mut libc::c_char
    } else {
        buf
    };
}
unsafe extern "C" fn handler(mut s: libc::c_int) {
    ::core::ptr::write_volatile(
        &mut signo[s as usize] as *mut sig_atomic_t,
        1 as libc::c_int,
    );
}
