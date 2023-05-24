use ::libc;
#[no_mangle]
pub unsafe extern "C" fn strmode(mut mode: libc::c_int, mut p: *mut libc::c_char) {
    match mode & 0o170000 as libc::c_int {
        16384 => {
            let fresh0 = p;
            p = p.offset(1);
            *fresh0 = 'd' as i32 as libc::c_char;
        }
        8192 => {
            let fresh1 = p;
            p = p.offset(1);
            *fresh1 = 'c' as i32 as libc::c_char;
        }
        24576 => {
            let fresh2 = p;
            p = p.offset(1);
            *fresh2 = 'b' as i32 as libc::c_char;
        }
        32768 => {
            let fresh3 = p;
            p = p.offset(1);
            *fresh3 = '-' as i32 as libc::c_char;
        }
        40960 => {
            let fresh4 = p;
            p = p.offset(1);
            *fresh4 = 'l' as i32 as libc::c_char;
        }
        49152 => {
            let fresh5 = p;
            p = p.offset(1);
            *fresh5 = 's' as i32 as libc::c_char;
        }
        4096 => {
            let fresh6 = p;
            p = p.offset(1);
            *fresh6 = 'p' as i32 as libc::c_char;
        }
        _ => {
            let fresh7 = p;
            p = p.offset(1);
            *fresh7 = '?' as i32 as libc::c_char;
        }
    }
    if mode & 0o400 as libc::c_int != 0 {
        let fresh8 = p;
        p = p.offset(1);
        *fresh8 = 'r' as i32 as libc::c_char;
    } else {
        let fresh9 = p;
        p = p.offset(1);
        *fresh9 = '-' as i32 as libc::c_char;
    }
    if mode & 0o200 as libc::c_int != 0 {
        let fresh10 = p;
        p = p.offset(1);
        *fresh10 = 'w' as i32 as libc::c_char;
    } else {
        let fresh11 = p;
        p = p.offset(1);
        *fresh11 = '-' as i32 as libc::c_char;
    }
    match mode & (0o100 as libc::c_int | 0o4000 as libc::c_int) {
        0 => {
            let fresh12 = p;
            p = p.offset(1);
            *fresh12 = '-' as i32 as libc::c_char;
        }
        64 => {
            let fresh13 = p;
            p = p.offset(1);
            *fresh13 = 'x' as i32 as libc::c_char;
        }
        2048 => {
            let fresh14 = p;
            p = p.offset(1);
            *fresh14 = 'S' as i32 as libc::c_char;
        }
        2112 => {
            let fresh15 = p;
            p = p.offset(1);
            *fresh15 = 's' as i32 as libc::c_char;
        }
        _ => {}
    }
    if mode & 0o400 as libc::c_int >> 3 as libc::c_int != 0 {
        let fresh16 = p;
        p = p.offset(1);
        *fresh16 = 'r' as i32 as libc::c_char;
    } else {
        let fresh17 = p;
        p = p.offset(1);
        *fresh17 = '-' as i32 as libc::c_char;
    }
    if mode & 0o200 as libc::c_int >> 3 as libc::c_int != 0 {
        let fresh18 = p;
        p = p.offset(1);
        *fresh18 = 'w' as i32 as libc::c_char;
    } else {
        let fresh19 = p;
        p = p.offset(1);
        *fresh19 = '-' as i32 as libc::c_char;
    }
    match mode & (0o100 as libc::c_int >> 3 as libc::c_int | 0o2000 as libc::c_int) {
        0 => {
            let fresh20 = p;
            p = p.offset(1);
            *fresh20 = '-' as i32 as libc::c_char;
        }
        8 => {
            let fresh21 = p;
            p = p.offset(1);
            *fresh21 = 'x' as i32 as libc::c_char;
        }
        1024 => {
            let fresh22 = p;
            p = p.offset(1);
            *fresh22 = 'S' as i32 as libc::c_char;
        }
        1032 => {
            let fresh23 = p;
            p = p.offset(1);
            *fresh23 = 's' as i32 as libc::c_char;
        }
        _ => {}
    }
    if mode & 0o400 as libc::c_int >> 3 as libc::c_int >> 3 as libc::c_int != 0 {
        let fresh24 = p;
        p = p.offset(1);
        *fresh24 = 'r' as i32 as libc::c_char;
    } else {
        let fresh25 = p;
        p = p.offset(1);
        *fresh25 = '-' as i32 as libc::c_char;
    }
    if mode & 0o200 as libc::c_int >> 3 as libc::c_int >> 3 as libc::c_int != 0 {
        let fresh26 = p;
        p = p.offset(1);
        *fresh26 = 'w' as i32 as libc::c_char;
    } else {
        let fresh27 = p;
        p = p.offset(1);
        *fresh27 = '-' as i32 as libc::c_char;
    }
    match mode
        & (0o100 as libc::c_int >> 3 as libc::c_int >> 3 as libc::c_int | 0o1000 as libc::c_int)
    {
        0 => {
            let fresh28 = p;
            p = p.offset(1);
            *fresh28 = '-' as i32 as libc::c_char;
        }
        1 => {
            let fresh29 = p;
            p = p.offset(1);
            *fresh29 = 'x' as i32 as libc::c_char;
        }
        512 => {
            let fresh30 = p;
            p = p.offset(1);
            *fresh30 = 'T' as i32 as libc::c_char;
        }
        513 => {
            let fresh31 = p;
            p = p.offset(1);
            *fresh31 = 't' as i32 as libc::c_char;
        }
        _ => {}
    }
    let fresh32 = p;
    p = p.offset(1);
    *fresh32 = ' ' as i32 as libc::c_char;
    *p = '\0' as i32 as libc::c_char;
}
