use ::libc;
extern "C" {
    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub const _ISspace: C2RustUnnamed = 8192;
pub type C2RustUnnamed = libc::c_uint;
pub const _ISalnum: C2RustUnnamed = 8;
pub const _ISpunct: C2RustUnnamed = 4;
pub const _IScntrl: C2RustUnnamed = 2;
pub const _ISblank: C2RustUnnamed = 1;
pub const _ISgraph: C2RustUnnamed = 32768;
pub const _ISprint: C2RustUnnamed = 16384;
pub const _ISxdigit: C2RustUnnamed = 4096;
pub const _ISdigit: C2RustUnnamed = 2048;
pub const _ISalpha: C2RustUnnamed = 1024;
pub const _ISlower: C2RustUnnamed = 512;
pub const _ISupper: C2RustUnnamed = 256;
static mut Base64: [libc::c_char; 65] = unsafe {
    *::core::mem::transmute::<&[u8; 65], &[libc::c_char; 65]>(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\0",
    )
};
static mut Pad64: libc::c_char = '=' as i32 as libc::c_char;
#[no_mangle]
pub unsafe extern "C" fn __b64_ntop(
    mut src: *const u_char,
    mut srclength: size_t,
    mut target: *mut libc::c_char,
    mut targsize: size_t,
) -> libc::c_int {
    let mut datalength: size_t = 0 as libc::c_int as size_t;
    let mut input: [u_char; 3] = [0; 3];
    let mut output: [u_char; 4] = [0; 4];
    let mut i: u_int = 0;
    while (2 as libc::c_int as libc::c_ulong) < srclength {
        let fresh0 = src;
        src = src.offset(1);
        input[0 as libc::c_int as usize] = *fresh0;
        let fresh1 = src;
        src = src.offset(1);
        input[1 as libc::c_int as usize] = *fresh1;
        let fresh2 = src;
        src = src.offset(1);
        input[2 as libc::c_int as usize] = *fresh2;
        srclength = (srclength as libc::c_ulong).wrapping_sub(3 as libc::c_int as libc::c_ulong)
            as size_t as size_t;
        output[0 as libc::c_int as usize] =
            (input[0 as libc::c_int as usize] as libc::c_int >> 2 as libc::c_int) as u_char;
        output[1 as libc::c_int as usize] = (((input[0 as libc::c_int as usize] as libc::c_int
            & 0x3 as libc::c_int)
            << 4 as libc::c_int)
            + (input[1 as libc::c_int as usize] as libc::c_int >> 4 as libc::c_int))
            as u_char;
        output[2 as libc::c_int as usize] = (((input[1 as libc::c_int as usize] as libc::c_int
            & 0xf as libc::c_int)
            << 2 as libc::c_int)
            + (input[2 as libc::c_int as usize] as libc::c_int >> 6 as libc::c_int))
            as u_char;
        output[3 as libc::c_int as usize] =
            (input[2 as libc::c_int as usize] as libc::c_int & 0x3f as libc::c_int) as u_char;
        if datalength.wrapping_add(4 as libc::c_int as libc::c_ulong) > targsize {
            return -(1 as libc::c_int);
        }
        let fresh3 = datalength;
        datalength = datalength.wrapping_add(1);
        *target.offset(fresh3 as isize) = Base64[output[0 as libc::c_int as usize] as usize];
        let fresh4 = datalength;
        datalength = datalength.wrapping_add(1);
        *target.offset(fresh4 as isize) = Base64[output[1 as libc::c_int as usize] as usize];
        let fresh5 = datalength;
        datalength = datalength.wrapping_add(1);
        *target.offset(fresh5 as isize) = Base64[output[2 as libc::c_int as usize] as usize];
        let fresh6 = datalength;
        datalength = datalength.wrapping_add(1);
        *target.offset(fresh6 as isize) = Base64[output[3 as libc::c_int as usize] as usize];
    }
    if 0 as libc::c_int as libc::c_ulong != srclength {
        input[2 as libc::c_int as usize] = '\0' as i32 as u_char;
        input[1 as libc::c_int as usize] = input[2 as libc::c_int as usize];
        input[0 as libc::c_int as usize] = input[1 as libc::c_int as usize];
        i = 0 as libc::c_int as u_int;
        while (i as libc::c_ulong) < srclength {
            let fresh7 = src;
            src = src.offset(1);
            input[i as usize] = *fresh7;
            i = i.wrapping_add(1);
            i;
        }
        output[0 as libc::c_int as usize] =
            (input[0 as libc::c_int as usize] as libc::c_int >> 2 as libc::c_int) as u_char;
        output[1 as libc::c_int as usize] = (((input[0 as libc::c_int as usize] as libc::c_int
            & 0x3 as libc::c_int)
            << 4 as libc::c_int)
            + (input[1 as libc::c_int as usize] as libc::c_int >> 4 as libc::c_int))
            as u_char;
        output[2 as libc::c_int as usize] = (((input[1 as libc::c_int as usize] as libc::c_int
            & 0xf as libc::c_int)
            << 2 as libc::c_int)
            + (input[2 as libc::c_int as usize] as libc::c_int >> 6 as libc::c_int))
            as u_char;
        if datalength.wrapping_add(4 as libc::c_int as libc::c_ulong) > targsize {
            return -(1 as libc::c_int);
        }
        let fresh8 = datalength;
        datalength = datalength.wrapping_add(1);
        *target.offset(fresh8 as isize) = Base64[output[0 as libc::c_int as usize] as usize];
        let fresh9 = datalength;
        datalength = datalength.wrapping_add(1);
        *target.offset(fresh9 as isize) = Base64[output[1 as libc::c_int as usize] as usize];
        if srclength == 1 as libc::c_int as libc::c_ulong {
            let fresh10 = datalength;
            datalength = datalength.wrapping_add(1);
            *target.offset(fresh10 as isize) = Pad64;
        } else {
            let fresh11 = datalength;
            datalength = datalength.wrapping_add(1);
            *target.offset(fresh11 as isize) = Base64[output[2 as libc::c_int as usize] as usize];
        }
        let fresh12 = datalength;
        datalength = datalength.wrapping_add(1);
        *target.offset(fresh12 as isize) = Pad64;
    }
    if datalength >= targsize {
        return -(1 as libc::c_int);
    }
    *target.offset(datalength as isize) = '\0' as i32 as libc::c_char;
    return datalength as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn __b64_pton(
    mut src: *const libc::c_char,
    mut target: *mut u_char,
    mut targsize: size_t,
) -> libc::c_int {
    let mut tarindex: u_int = 0;
    let mut state: u_int = 0;
    let mut ch: libc::c_int = 0;
    let mut pos: *mut libc::c_char = 0 as *mut libc::c_char;
    state = 0 as libc::c_int as u_int;
    tarindex = 0 as libc::c_int as u_int;
    loop {
        let fresh13 = src;
        src = src.offset(1);
        ch = *fresh13 as libc::c_int;
        if !(ch != '\0' as i32) {
            break;
        }
        if *(*__ctype_b_loc()).offset(ch as isize) as libc::c_int
            & _ISspace as libc::c_int as libc::c_ushort as libc::c_int
            != 0
        {
            continue;
        }
        if ch == Pad64 as libc::c_int {
            break;
        }
        pos = strchr(Base64.as_ptr(), ch);
        if pos.is_null() {
            return -(1 as libc::c_int);
        }
        match state {
            0 => {
                if !target.is_null() {
                    if tarindex as libc::c_ulong >= targsize {
                        return -(1 as libc::c_int);
                    }
                    *target.offset(tarindex as isize) =
                        ((pos.offset_from(Base64.as_ptr()) as libc::c_long) << 2 as libc::c_int)
                            as u_char;
                }
                state = 1 as libc::c_int as u_int;
            }
            1 => {
                if !target.is_null() {
                    if tarindex.wrapping_add(1 as libc::c_int as libc::c_uint) as libc::c_ulong
                        >= targsize
                    {
                        return -(1 as libc::c_int);
                    }
                    let ref mut fresh14 = *target.offset(tarindex as isize);
                    *fresh14 = (*fresh14 as libc::c_long
                        | pos.offset_from(Base64.as_ptr()) as libc::c_long >> 4 as libc::c_int)
                        as u_char;
                    *target
                        .offset(tarindex.wrapping_add(1 as libc::c_int as libc::c_uint) as isize) =
                        ((pos.offset_from(Base64.as_ptr()) as libc::c_long
                            & 0xf as libc::c_int as libc::c_long)
                            << 4 as libc::c_int) as u_char;
                }
                tarindex = tarindex.wrapping_add(1);
                tarindex;
                state = 2 as libc::c_int as u_int;
            }
            2 => {
                if !target.is_null() {
                    if tarindex.wrapping_add(1 as libc::c_int as libc::c_uint) as libc::c_ulong
                        >= targsize
                    {
                        return -(1 as libc::c_int);
                    }
                    let ref mut fresh15 = *target.offset(tarindex as isize);
                    *fresh15 = (*fresh15 as libc::c_long
                        | pos.offset_from(Base64.as_ptr()) as libc::c_long >> 2 as libc::c_int)
                        as u_char;
                    *target
                        .offset(tarindex.wrapping_add(1 as libc::c_int as libc::c_uint) as isize) =
                        ((pos.offset_from(Base64.as_ptr()) as libc::c_long
                            & 0x3 as libc::c_int as libc::c_long)
                            << 6 as libc::c_int) as u_char;
                }
                tarindex = tarindex.wrapping_add(1);
                tarindex;
                state = 3 as libc::c_int as u_int;
            }
            3 => {
                if !target.is_null() {
                    if tarindex as libc::c_ulong >= targsize {
                        return -(1 as libc::c_int);
                    }
                    let ref mut fresh16 = *target.offset(tarindex as isize);
                    *fresh16 = (*fresh16 as libc::c_long
                        | pos.offset_from(Base64.as_ptr()) as libc::c_long)
                        as u_char;
                }
                tarindex = tarindex.wrapping_add(1);
                tarindex;
                state = 0 as libc::c_int as u_int;
            }
            _ => {}
        }
    }
    if ch == Pad64 as libc::c_int {
        let fresh17 = src;
        src = src.offset(1);
        ch = *fresh17 as libc::c_int;
        let mut current_block_46: u64;
        match state {
            0 | 1 => return -(1 as libc::c_int),
            2 => {
                while ch != '\0' as i32 {
                    if *(*__ctype_b_loc()).offset(ch as isize) as libc::c_int
                        & _ISspace as libc::c_int as libc::c_ushort as libc::c_int
                        == 0
                    {
                        break;
                    }
                    let fresh18 = src;
                    src = src.offset(1);
                    ch = *fresh18 as libc::c_int;
                }
                if ch != Pad64 as libc::c_int {
                    return -(1 as libc::c_int);
                }
                let fresh19 = src;
                src = src.offset(1);
                ch = *fresh19 as libc::c_int;
                current_block_46 = 15691931973087213840;
            }
            3 => {
                current_block_46 = 15691931973087213840;
            }
            _ => {
                current_block_46 = 1434579379687443766;
            }
        }
        match current_block_46 {
            15691931973087213840 => {
                while ch != '\0' as i32 {
                    if *(*__ctype_b_loc()).offset(ch as isize) as libc::c_int
                        & _ISspace as libc::c_int as libc::c_ushort as libc::c_int
                        == 0
                    {
                        return -(1 as libc::c_int);
                    }
                    let fresh20 = src;
                    src = src.offset(1);
                    ch = *fresh20 as libc::c_int;
                }
                if !target.is_null()
                    && *target.offset(tarindex as isize) as libc::c_int != 0 as libc::c_int
                {
                    return -(1 as libc::c_int);
                }
            }
            _ => {}
        }
    } else if state != 0 as libc::c_int as libc::c_uint {
        return -(1 as libc::c_int);
    }
    return tarindex as libc::c_int;
}
