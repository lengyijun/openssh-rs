use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn __errno_location() -> *mut libc::c_int;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn fscanf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn rewind(__stream: *mut FILE);
    fn strerror(_: libc::c_int) -> *mut libc::c_char;

}
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type size_t = libc::c_ulong;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub path: *mut libc::c_char,
    pub value: libc::c_int,
}
static mut oom_adj_save: libc::c_int = -(2147483647 as libc::c_int) - 1 as libc::c_int;
static mut oom_adj_path: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
#[no_mangle]
pub static mut oom_adjust: [C2RustUnnamed; 3] = [
    {
        let mut init = C2RustUnnamed {
            path: b"/proc/self/oom_score_adj\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            value: -(1000 as libc::c_int),
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            path: b"/proc/self/oom_adj\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            value: -(17 as libc::c_int),
        };
        init
    },
    {
        let mut init = C2RustUnnamed {
            path: 0 as *const libc::c_char as *mut libc::c_char,
            value: 0 as libc::c_int,
        };
        init
    },
];
#[no_mangle]
pub unsafe extern "C" fn oom_adjust_setup() {
    let mut i: libc::c_int = 0;
    let mut value: libc::c_int = 0;
    let mut fp: *mut FILE = 0 as *mut FILE;
    crate::log::sshlog(
        b"port-linux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"oom_adjust_setup\0")).as_ptr(),
        266 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"oom_adjust_setup\0")).as_ptr(),
    );
    i = 0 as libc::c_int;
    while !(oom_adjust[i as usize].path).is_null() {
        oom_adj_path = oom_adjust[i as usize].path;
        value = oom_adjust[i as usize].value;
        fp = fopen(oom_adj_path, b"r+\0" as *const u8 as *const libc::c_char);
        if !fp.is_null() {
            if fscanf(
                fp,
                b"%d\0" as *const u8 as *const libc::c_char,
                &mut oom_adj_save as *mut libc::c_int,
            ) != 1 as libc::c_int
            {
                crate::log::sshlog(
                    b"port-linux.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                        b"oom_adjust_setup\0",
                    ))
                    .as_ptr(),
                    273 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_VERBOSE,
                    0 as *const libc::c_char,
                    b"error reading %s: %s\0" as *const u8 as *const libc::c_char,
                    oom_adj_path,
                    strerror(*__errno_location()),
                );
            } else {
                rewind(fp);
                if fprintf(fp, b"%d\n\0" as *const u8 as *const libc::c_char, value)
                    <= 0 as libc::c_int
                {
                    crate::log::sshlog(
                        b"port-linux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                            b"oom_adjust_setup\0",
                        ))
                        .as_ptr(),
                        278 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_VERBOSE,
                        0 as *const libc::c_char,
                        b"error writing %s: %s\0" as *const u8 as *const libc::c_char,
                        oom_adj_path,
                        strerror(*__errno_location()),
                    );
                } else {
                    crate::log::sshlog(
                        b"port-linux.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                            b"oom_adjust_setup\0",
                        ))
                        .as_ptr(),
                        281 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"Set %s from %d to %d\0" as *const u8 as *const libc::c_char,
                        oom_adj_path,
                        oom_adj_save,
                        value,
                    );
                }
            }
            fclose(fp);
            return;
        }
        i += 1;
        i;
    }
    oom_adj_path = 0 as *mut libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn oom_adjust_restore() {
    let mut fp: *mut FILE = 0 as *mut FILE;
    crate::log::sshlog(
        b"port-linux.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"oom_adjust_restore\0"))
            .as_ptr(),
        296 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"%s\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"oom_adjust_restore\0"))
            .as_ptr(),
    );
    if oom_adj_save == -(2147483647 as libc::c_int) - 1 as libc::c_int
        || oom_adj_path.is_null()
        || {
            fp = fopen(oom_adj_path, b"w\0" as *const u8 as *const libc::c_char);
            fp.is_null()
        }
    {
        return;
    }
    if fprintf(
        fp,
        b"%d\n\0" as *const u8 as *const libc::c_char,
        oom_adj_save,
    ) <= 0 as libc::c_int
    {
        crate::log::sshlog(
            b"port-linux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"oom_adjust_restore\0"))
                .as_ptr(),
            302 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"error writing %s: %s\0" as *const u8 as *const libc::c_char,
            oom_adj_path,
            strerror(*__errno_location()),
        );
    } else {
        crate::log::sshlog(
            b"port-linux.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"oom_adjust_restore\0"))
                .as_ptr(),
            304 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Set %s to %d\0" as *const u8 as *const libc::c_char,
            oom_adj_path,
            oom_adj_save,
        );
    }
    fclose(fp);
}
