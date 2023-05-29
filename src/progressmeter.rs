use crate::atomicio::atomicio;
use ::libc;
extern "C" {
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn alarm(__seconds: libc::c_uint) -> libc::c_uint;
    fn getpgrp() -> __pid_t;
    fn tcgetpgrp(__fd: libc::c_int) -> __pid_t;

    fn ioctl(__fd: libc::c_int, __request: libc::c_ulong, _: ...) -> libc::c_int;

    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn xextendf(
        s: *mut *mut libc::c_char,
        sep: *const libc::c_char,
        fmt: *const libc::c_char,
        _: ...
    );

    fn asmprintf(
        _: *mut *mut libc::c_char,
        _: size_t,
        _: *mut libc::c_int,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
}
pub type __off_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __ssize_t = libc::c_long;
pub type __sig_atomic_t = libc::c_int;
pub type off_t = __off_t;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type sig_atomic_t = __sig_atomic_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct winsize {
    pub ws_row: libc::c_ushort,
    pub ws_col: libc::c_ushort,
    pub ws_xpixel: libc::c_ushort,
    pub ws_ypixel: libc::c_ushort,
}
pub type sshsig_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
static mut start: libc::c_double = 0.;
static mut last_update: libc::c_double = 0.;
static mut file: *const libc::c_char = 0 as *const libc::c_char;
static mut start_pos: off_t = 0;
static mut end_pos: off_t = 0;
static mut cur_pos: off_t = 0;
static mut counter: *mut off_t = 0 as *const off_t as *mut off_t;
static mut stalled: libc::c_long = 0;
static mut bytes_per_second: libc::c_int = 0;
static mut win_size: libc::c_int = 0;
static mut win_resized: sig_atomic_t = 0;
static mut alarm_fired: sig_atomic_t = 0;
static mut unit: [libc::c_char; 6] =
    unsafe { *::core::mem::transmute::<&[u8; 6], &[libc::c_char; 6]>(b" KMGT\0") };
unsafe extern "C" fn can_output() -> libc::c_int {
    return (getpgrp() == tcgetpgrp(1 as libc::c_int)) as libc::c_int;
}
unsafe extern "C" fn format_rate(mut bytes: off_t) -> *const libc::c_char {
    let mut i: libc::c_int = 0;
    static mut buf: [libc::c_char; 68] = [0; 68];
    bytes *= 100 as libc::c_int as libc::c_long;
    i = 0 as libc::c_int;
    while bytes >= (100 as libc::c_int * 1000 as libc::c_int) as libc::c_long
        && unit[i as usize] as libc::c_int != 'T' as i32
    {
        bytes = (bytes + 512 as libc::c_int as libc::c_long) / 1024 as libc::c_int as libc::c_long;
        i += 1;
        i;
    }
    if i == 0 as libc::c_int {
        i += 1;
        i;
        bytes = (bytes + 512 as libc::c_int as libc::c_long) / 1024 as libc::c_int as libc::c_long;
    }
    libc::snprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 68]>() as usize,
        b"%3lld.%1lld%c%s\0" as *const u8 as *const libc::c_char,
        (bytes + 5 as libc::c_int as libc::c_long) as libc::c_longlong
            / 100 as libc::c_int as libc::c_longlong,
        (bytes + 5 as libc::c_int as libc::c_long) as libc::c_longlong
            / 10 as libc::c_int as libc::c_longlong
            % 10 as libc::c_int as libc::c_longlong,
        unit[i as usize] as libc::c_int,
        if i != 0 {
            b"B\0" as *const u8 as *const libc::c_char
        } else {
            b" \0" as *const u8 as *const libc::c_char
        },
    );
    return buf.as_mut_ptr();
}
unsafe extern "C" fn format_size(mut bytes: off_t) -> *const libc::c_char {
    let mut i: libc::c_int = 0;
    static mut buf: [libc::c_char; 42] = [0; 42];
    i = 0 as libc::c_int;
    while bytes >= 10000 as libc::c_int as libc::c_long
        && unit[i as usize] as libc::c_int != 'T' as i32
    {
        bytes = (bytes + 512 as libc::c_int as libc::c_long) / 1024 as libc::c_int as libc::c_long;
        i += 1;
        i;
    }
    libc::snprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 42]>() as usize,
        b"%4lld%c%s\0" as *const u8 as *const libc::c_char,
        bytes as libc::c_longlong,
        unit[i as usize] as libc::c_int,
        if i != 0 {
            b"B\0" as *const u8 as *const libc::c_char
        } else {
            b" \0" as *const u8 as *const libc::c_char
        },
    );
    return buf.as_mut_ptr();
}
pub unsafe extern "C" fn refresh_progress_meter(mut force_update: libc::c_int) {
    let mut buf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut obuf: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut transferred: off_t = 0;
    let mut elapsed: libc::c_double = 0.;
    let mut now: libc::c_double = 0.;
    let mut percent: libc::c_int = 0;
    let mut bytes_left: off_t = 0;
    let mut cur_speed: libc::c_int = 0;
    let mut hours: libc::c_int = 0;
    let mut minutes: libc::c_int = 0;
    let mut seconds: libc::c_int = 0;
    let mut file_len: libc::c_int = 0;
    let mut cols: libc::c_int = 0;
    if force_update == 0 && alarm_fired == 0 && win_resized == 0 || can_output() == 0 {
        return;
    }
    ::core::ptr::write_volatile(&mut alarm_fired as *mut sig_atomic_t, 0 as libc::c_int);
    if win_resized != 0 {
        setscreensize();
        ::core::ptr::write_volatile(&mut win_resized as *mut sig_atomic_t, 0 as libc::c_int);
    }
    transferred = *counter - (if cur_pos != 0 { cur_pos } else { start_pos });
    cur_pos = *counter;
    now = crate::misc::monotime_double();
    bytes_left = end_pos - cur_pos;
    if bytes_left > 0 as libc::c_int as libc::c_long {
        elapsed = now - last_update;
    } else {
        elapsed = now - start;
        transferred = end_pos - start_pos;
        bytes_per_second = 0 as libc::c_int;
    }
    if elapsed != 0 as libc::c_int as libc::c_double {
        cur_speed = (transferred as libc::c_double / elapsed) as libc::c_int;
    } else {
        cur_speed = transferred as libc::c_int;
    }
    if bytes_per_second != 0 as libc::c_int {
        bytes_per_second = (bytes_per_second as libc::c_double * 0.9f64
            + cur_speed as libc::c_double * (1.0f64 - 0.9f64))
            as libc::c_int;
    } else {
        bytes_per_second = cur_speed;
    }
    last_update = now;
    if win_size < 4 as libc::c_int {
        return;
    }
    cols = win_size - 36 as libc::c_int;
    file_len = cols;
    if file_len > 0 as libc::c_int {
        asmprintf(
            &mut buf as *mut *mut libc::c_char,
            2147483647 as libc::c_int as size_t,
            &mut cols as *mut libc::c_int,
            b"%-*s\0" as *const u8 as *const libc::c_char,
            file_len,
            file,
        );
        if cols < file_len {
            xextendf(
                &mut buf as *mut *mut libc::c_char,
                0 as *const libc::c_char,
                b"%*s\0" as *const u8 as *const libc::c_char,
                file_len - cols,
                b"\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if end_pos == 0 as libc::c_int as libc::c_long || cur_pos == end_pos {
        percent = 100 as libc::c_int;
    } else {
        percent = (cur_pos as libc::c_float / end_pos as libc::c_float
            * 100 as libc::c_int as libc::c_float) as libc::c_int;
    }
    xextendf(
        &mut buf as *mut *mut libc::c_char,
        0 as *const libc::c_char,
        b" %3d%% %s %s/s \0" as *const u8 as *const libc::c_char,
        percent,
        format_size(cur_pos),
        format_rate(bytes_per_second as off_t),
    );
    if transferred == 0 {
        stalled = (stalled as libc::c_double + elapsed) as libc::c_long;
    } else {
        stalled = 0 as libc::c_int as libc::c_long;
    }
    if stalled >= 5 as libc::c_int as libc::c_long {
        xextendf(
            &mut buf as *mut *mut libc::c_char,
            0 as *const libc::c_char,
            b"- stalled -\0" as *const u8 as *const libc::c_char,
        );
    } else if bytes_per_second == 0 as libc::c_int && bytes_left != 0 {
        xextendf(
            &mut buf as *mut *mut libc::c_char,
            0 as *const libc::c_char,
            b"  --:-- ETA\0" as *const u8 as *const libc::c_char,
        );
    } else {
        if bytes_left > 0 as libc::c_int as libc::c_long {
            seconds = (bytes_left / bytes_per_second as libc::c_long) as libc::c_int;
        } else {
            seconds = elapsed as libc::c_int;
        }
        hours = seconds / 3600 as libc::c_int;
        seconds -= hours * 3600 as libc::c_int;
        minutes = seconds / 60 as libc::c_int;
        seconds -= minutes * 60 as libc::c_int;
        if hours != 0 as libc::c_int {
            xextendf(
                &mut buf as *mut *mut libc::c_char,
                0 as *const libc::c_char,
                b"%d:%02d:%02d\0" as *const u8 as *const libc::c_char,
                hours,
                minutes,
                seconds,
            );
        } else {
            xextendf(
                &mut buf as *mut *mut libc::c_char,
                0 as *const libc::c_char,
                b"  %02d:%02d\0" as *const u8 as *const libc::c_char,
                minutes,
                seconds,
            );
        }
        if bytes_left > 0 as libc::c_int as libc::c_long {
            xextendf(
                &mut buf as *mut *mut libc::c_char,
                0 as *const libc::c_char,
                b" ETA\0" as *const u8 as *const libc::c_char,
            );
        } else {
            xextendf(
                &mut buf as *mut *mut libc::c_char,
                0 as *const libc::c_char,
                b"    \0" as *const u8 as *const libc::c_char,
            );
        }
    }
    cols = win_size - 1 as libc::c_int;
    asmprintf(
        &mut obuf as *mut *mut libc::c_char,
        2147483647 as libc::c_int as size_t,
        &mut cols as *mut libc::c_int,
        b" %s\0" as *const u8 as *const libc::c_char,
        buf,
    );
    if !obuf.is_null() {
        *obuf = '\r' as i32 as libc::c_char;
        atomicio(
            ::core::mem::transmute::<
                Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
                Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
            >(Some(
                write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
            )),
            1 as libc::c_int,
            obuf as *mut libc::c_void,
            strlen(obuf),
        );
    }
    libc::free(buf as *mut libc::c_void);
    libc::free(obuf as *mut libc::c_void);
}
unsafe extern "C" fn sig_alarm(mut _ignore: libc::c_int) {
    ::core::ptr::write_volatile(&mut alarm_fired as *mut sig_atomic_t, 1 as libc::c_int);
    alarm(1 as libc::c_int as libc::c_uint);
}
pub unsafe extern "C" fn start_progress_meter(
    mut f: *const libc::c_char,
    mut filesize: off_t,
    mut ctr: *mut off_t,
) {
    last_update = crate::misc::monotime_double();
    start = last_update;
    file = f;
    start_pos = *ctr;
    end_pos = filesize;
    cur_pos = 0 as libc::c_int as off_t;
    counter = ctr as *mut off_t;
    stalled = 0 as libc::c_int as libc::c_long;
    bytes_per_second = 0 as libc::c_int;
    setscreensize();
    refresh_progress_meter(1 as libc::c_int);
    crate::misc::ssh_signal(
        14 as libc::c_int,
        Some(sig_alarm as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    crate::misc::ssh_signal(
        28 as libc::c_int,
        Some(sig_winch as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    alarm(1 as libc::c_int as libc::c_uint);
}
pub unsafe extern "C" fn stop_progress_meter() {
    alarm(0 as libc::c_int as libc::c_uint);
    if can_output() == 0 {
        return;
    }
    if cur_pos != end_pos {
        refresh_progress_meter(1 as libc::c_int);
    }
    atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        1 as libc::c_int,
        b"\n\0" as *const u8 as *const libc::c_char as *mut libc::c_void,
        1 as libc::c_int as size_t,
    );
}
unsafe extern "C" fn sig_winch(mut _sig: libc::c_int) {
    ::core::ptr::write_volatile(&mut win_resized as *mut sig_atomic_t, 1 as libc::c_int);
}
unsafe extern "C" fn setscreensize() {
    let mut winsize: winsize = winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    if ioctl(
        1 as libc::c_int,
        0x5413 as libc::c_int as libc::c_ulong,
        &mut winsize as *mut winsize,
    ) != -(1 as libc::c_int)
        && winsize.ws_col as libc::c_int != 0 as libc::c_int
    {
        if winsize.ws_col as libc::c_int > 512 as libc::c_int {
            win_size = 512 as libc::c_int;
        } else {
            win_size = winsize.ws_col as libc::c_int;
        }
    } else {
        win_size = 80 as libc::c_int;
    }
    win_size += 1 as libc::c_int;
}
