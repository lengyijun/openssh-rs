use crate::atomicio::atomicio;
use crate::log::log_init;
use crate::misc::arglist;
use crate::misc::colon;
use crate::misc::parse_uri;
use crate::misc::parse_user_host_path;
use crate::openbsd_compat::vis::strnvis;
use crate::sftp_client::can_expand_path;
use crate::sftp_client::crossload_dir;
use crate::sftp_client::do_crossload;
use crate::sftp_client::do_expand_path;
use crate::sftp_client::do_init;
use crate::sftp_client::do_mkdir;
use crate::sftp_client::do_stat;
use crate::sftp_client::do_upload;
use crate::sftp_client::download_dir;
use crate::sftp_client::globpath_is_dir;
use crate::sftp_client::path_append;
use crate::sftp_client::remote_is_dir;
use crate::sftp_client::sftp_conn;
use crate::sftp_client::upload_dir;
use crate::sftp_common::Attrib;
use crate::utf8::fmprintf;
use crate::utf8::msetlocale;
use crate::utf8::snmprintf;
use crate::utf8::vasnmprintf;
use crate::utf8::vfmprintf;
use ::libc;
use libc::close;
use libc::kill;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type __dirstream;
    static mut stderr: *mut libc::FILE;

    fn vfprintf(_: *mut libc::FILE, _: *const libc::c_char, _: ::core::ffi::VaList) -> libc::c_int;

    fn getpwuid(__uid: __uid_t) -> *mut libc::passwd;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;

    fn execvp(__file: *const libc::c_char, __argv: *const *mut libc::c_char) -> libc::c_int;

    
    
    
    fn isatty(__fd: libc::c_int) -> libc::c_int;
    static mut BSDoptarg: *mut libc::c_char;
    static mut BSDoptind: libc::c_int;

    
    
    

    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    fn opendir(__name: *const libc::c_char) -> *mut DIR;
    fn closedir(__dirp: *mut DIR) -> libc::c_int;
    fn readdir(__dirp: *mut DIR) -> *mut dirent;
    fn fnmatch(
        __pattern: *const libc::c_char,
        __name: *const libc::c_char,
        __flags: libc::c_int,
    ) -> libc::c_int;
    fn _ssh__compat_globfree(_: *mut _ssh_compat_glob_t);
    fn __xpg_basename(__path: *mut libc::c_char) -> *mut libc::c_char;
    fn strtol(_: *const libc::c_char, _: *mut *mut libc::c_char, _: libc::c_int) -> libc::c_long;

    fn reallocarray(__ptr: *mut libc::c_void, __nmemb: size_t, __size: size_t)
        -> *mut libc::c_void;

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strrchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn xmalloc(_: size_t) -> *mut libc::c_void;
    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn xrecallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn xasprintf(_: *mut *mut libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn atomicio6(
        f: Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        fd: libc::c_int,
        _s: *mut libc::c_void,
        n: size_t,
        cb: Option<unsafe extern "C" fn(*mut libc::c_void, size_t) -> libc::c_int>,
        _: *mut libc::c_void,
    ) -> size_t;

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

    
    fn ssh_signal(_: libc::c_int, _: sshsig_t) -> sshsig_t;
    fn start_progress_meter(_: *const libc::c_char, _: off_t, _: *mut off_t);
    fn refresh_progress_meter(_: libc::c_int);
    fn stop_progress_meter();

    static mut __progname: *mut libc::c_char;
    fn remote_glob(
        _: *mut sftp_conn,
        _: *const libc::c_char,
        _: libc::c_int,
        _: Option<unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> libc::c_int>,
        _: *mut _ssh_compat_glob_t,
    ) -> libc::c_int;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type __u_int = libc::c_uint;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __sig_atomic_t = libc::c_int;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type uid_t = __uid_t;
pub type off_t = __off_t;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;

pub type __socket_type = libc::c_uint;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;



pub type _IO_lock_t = ();

pub type sig_atomic_t = __sig_atomic_t;
pub type va_list = __builtin_va_list;
pub type C2RustUnnamed = libc::c_uint;
pub const _ISalnum: C2RustUnnamed = 8;
pub const _ISpunct: C2RustUnnamed = 4;
pub const _IScntrl: C2RustUnnamed = 2;
pub const _ISblank: C2RustUnnamed = 1;
pub const _ISgraph: C2RustUnnamed = 32768;
pub const _ISprint: C2RustUnnamed = 16384;
pub const _ISspace: C2RustUnnamed = 8192;
pub const _ISxdigit: C2RustUnnamed = 4096;
pub const _ISdigit: C2RustUnnamed = 2048;
pub const _ISalpha: C2RustUnnamed = 1024;
pub const _ISlower: C2RustUnnamed = 512;
pub const _ISupper: C2RustUnnamed = 256;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dirent {
    pub d_ino: __ino_t,
    pub d_off: __off_t,
    pub d_reclen: libc::c_ushort,
    pub d_type: libc::c_uchar,
    pub d_name: [libc::c_char; 256],
}
pub type DIR = __dirstream;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _ssh_compat_glob_t {
    pub gl_pathc: size_t,
    pub gl_matchc: size_t,
    pub gl_offs: size_t,
    pub gl_flags: libc::c_int,
    pub gl_pathv: *mut *mut libc::c_char,
    pub gl_statv: *mut *mut libc::stat,
    pub gl_errfunc: Option<unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> libc::c_int>,
    pub gl_closedir: Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
    pub gl_readdir: Option<unsafe extern "C" fn(*mut libc::c_void) -> *mut dirent>,
    pub gl_opendir: Option<unsafe extern "C" fn(*const libc::c_char) -> *mut libc::c_void>,
    pub gl_lstat: Option<unsafe extern "C" fn(*const libc::c_char, *mut libc::stat) -> libc::c_int>,
    pub gl_stat: Option<unsafe extern "C" fn(*const libc::c_char, *mut libc::stat) -> libc::c_int>,
}
pub type SyslogFacility = libc::c_int;
pub const SYSLOG_FACILITY_NOT_SET: SyslogFacility = -1;
pub const SYSLOG_FACILITY_LOCAL7: SyslogFacility = 10;
pub const SYSLOG_FACILITY_LOCAL6: SyslogFacility = 9;
pub const SYSLOG_FACILITY_LOCAL5: SyslogFacility = 8;
pub const SYSLOG_FACILITY_LOCAL4: SyslogFacility = 7;
pub const SYSLOG_FACILITY_LOCAL3: SyslogFacility = 6;
pub const SYSLOG_FACILITY_LOCAL2: SyslogFacility = 5;
pub const SYSLOG_FACILITY_LOCAL1: SyslogFacility = 4;
pub const SYSLOG_FACILITY_LOCAL0: SyslogFacility = 3;
pub const SYSLOG_FACILITY_AUTH: SyslogFacility = 2;
pub const SYSLOG_FACILITY_USER: SyslogFacility = 1;
pub const SYSLOG_FACILITY_DAEMON: SyslogFacility = 0;
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

pub type sshsig_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct BUF {
    pub cnt: size_t,
    pub buf: *mut libc::c_char,
}
pub type scp_mode_e = libc::c_uint;
pub const MODE_SFTP: scp_mode_e = 1;
pub const MODE_SCP: scp_mode_e = 0;
pub static mut args: arglist = arglist {
    list: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    num: 0,
    nalloc: 0,
};
pub static mut remote_remote_args: arglist = arglist {
    list: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    num: 0,
    nalloc: 0,
};
pub static mut limit_kbps: libc::c_longlong = 0 as libc::c_int as libc::c_longlong;
pub static mut bwlimit: crate::misc::bwlimit = crate::misc::bwlimit {
    buflen: 0,
    rate: 0,
    thresh: 0,
    lamt: 0,
    bwstart: libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    },
    bwend: libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    },
};
pub static mut curfile: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
pub static mut verbose_mode: libc::c_int = 0 as libc::c_int;
pub static mut log_level: LogLevel = SYSLOG_LEVEL_INFO;
pub static mut showprogress: libc::c_int = 1 as libc::c_int;
pub static mut throughlocal: libc::c_int = 1 as libc::c_int;
pub static mut sshport: libc::c_int = -(1 as libc::c_int);
pub static mut ssh_program: *mut libc::c_char =
    b"/usr/local/bin/ssh\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
pub static mut do_cmd_pid: pid_t = -(1 as libc::c_int);
pub static mut do_cmd_pid2: pid_t = -(1 as libc::c_int);
pub static mut sftp_copy_buflen: size_t = 0;
pub static mut sftp_nrequests: size_t = 0;
pub static mut interrupted: sig_atomic_t = 0 as libc::c_int;
unsafe extern "C" fn killchild(mut signo: libc::c_int) {
    if do_cmd_pid > 1 as libc::c_int {
        kill(
            do_cmd_pid,
            if signo != 0 { signo } else { 15 as libc::c_int },
        );
        libc::waitpid(do_cmd_pid, 0 as *mut libc::c_int, 0 as libc::c_int);
    }
    if do_cmd_pid2 > 1 as libc::c_int {
        kill(
            do_cmd_pid2,
            if signo != 0 { signo } else { 15 as libc::c_int },
        );
        libc::waitpid(do_cmd_pid2, 0 as *mut libc::c_int, 0 as libc::c_int);
    }
    if signo != 0 {
        libc::_exit(1 as libc::c_int);
    }
    libc::exit(1 as libc::c_int);
}
unsafe extern "C" fn suspone(mut pid: libc::c_int, mut signo: libc::c_int) {
    let mut status: libc::c_int = 0;
    if pid > 1 as libc::c_int {
        kill(pid, signo);
        while libc::waitpid(pid, &mut status, 2 as libc::c_int) == -(1 as libc::c_int)
            && *libc::__errno_location() == 4 as libc::c_int
        {}
    }
}
unsafe extern "C" fn suspchild(mut signo: libc::c_int) {
    suspone(do_cmd_pid, signo);
    suspone(do_cmd_pid2, signo);
    kill(libc::getpid(), 19 as libc::c_int);
}
unsafe extern "C" fn do_local_cmd(mut a: *mut arglist) -> libc::c_int {
    let mut i: u_int = 0;
    let mut status: libc::c_int = 0;
    let mut pid: pid_t = 0;
    if (*a).num == 0 as libc::c_int as libc::c_uint {
        sshfatal(
            b"scp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_local_cmd\0")).as_ptr(),
            238 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"do_local_cmd: no arguments\0" as *const u8 as *const libc::c_char,
        );
    }
    if verbose_mode != 0 {
        libc::fprintf(stderr, b"Executing:\0" as *const u8 as *const libc::c_char);
        i = 0 as libc::c_int as u_int;
        while i < (*a).num {
            fmprintf(
                stderr,
                b" %s\0" as *const u8 as *const libc::c_char,
                *((*a).list).offset(i as isize),
            );
            i = i.wrapping_add(1);
            i;
        }
        libc::fprintf(stderr, b"\n\0" as *const u8 as *const libc::c_char);
    }
    pid = libc::fork();
    if pid == -(1 as libc::c_int) {
        sshfatal(
            b"scp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_local_cmd\0")).as_ptr(),
            247 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"do_local_cmd: libc::fork: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    if pid == 0 as libc::c_int {
        execvp(
            *((*a).list).offset(0 as libc::c_int as isize),
            (*a).list as *const *mut libc::c_char,
        );
        libc::perror(*((*a).list).offset(0 as libc::c_int as isize));
        libc::exit(1 as libc::c_int);
    }
    do_cmd_pid = pid;
    ssh_signal(
        15 as libc::c_int,
        Some(killchild as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    ssh_signal(
        2 as libc::c_int,
        Some(killchild as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    ssh_signal(
        1 as libc::c_int,
        Some(killchild as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    while libc::waitpid(pid, &mut status, 0 as libc::c_int) == -(1 as libc::c_int) {
        if *libc::__errno_location() != 4 as libc::c_int {
            sshfatal(
                b"scp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_local_cmd\0"))
                    .as_ptr(),
                262 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"do_local_cmd: libc::waitpid: %s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
    }
    do_cmd_pid = -(1 as libc::c_int);
    if !(status & 0x7f as libc::c_int == 0 as libc::c_int)
        || (status & 0xff00 as libc::c_int) >> 8 as libc::c_int != 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn do_cmd(
    mut program: *mut libc::c_char,
    mut host: *mut libc::c_char,
    mut remuser: *mut libc::c_char,
    mut port: libc::c_int,
    mut subsystem: libc::c_int,
    mut cmd_0: *mut libc::c_char,
    mut fdin: *mut libc::c_int,
    mut fdout: *mut libc::c_int,
    mut pid: *mut pid_t,
) -> libc::c_int {
    let mut sv: [libc::c_int; 2] = [0; 2];
    if verbose_mode != 0 {
        fmprintf(
            stderr,
            b"Executing: program %s host %s, user %s, command %s\n\0" as *const u8
                as *const libc::c_char,
            program,
            host,
            if !remuser.is_null() {
                remuser as *const libc::c_char
            } else {
                b"(unspecified)\0" as *const u8 as *const libc::c_char
            },
            cmd_0,
        );
    }
    if port == -(1 as libc::c_int) {
        port = sshport;
    }
    if libc::socketpair(
        1 as libc::c_int,
        SOCK_STREAM as libc::c_int,
        0 as libc::c_int,
        sv.as_mut_ptr(),
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"scp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 7], &[libc::c_char; 7]>(b"do_cmd\0")).as_ptr(),
            303 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::socketpair: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    ssh_signal(
        20 as libc::c_int,
        Some(suspchild as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    ssh_signal(
        21 as libc::c_int,
        Some(suspchild as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    ssh_signal(
        22 as libc::c_int,
        Some(suspchild as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    *pid = libc::fork();
    match *pid {
        -1 => {
            sshfatal(
                b"scp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 7], &[libc::c_char; 7]>(b"do_cmd\0")).as_ptr(),
                314 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"libc::fork: %s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
        0 => {
            if libc::dup2(sv[0 as libc::c_int as usize], 0 as libc::c_int) == -(1 as libc::c_int)
                || libc::dup2(sv[0 as libc::c_int as usize], 1 as libc::c_int)
                    == -(1 as libc::c_int)
            {
                crate::log::sshlog(
                    b"scp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 7], &[libc::c_char; 7]>(b"do_cmd\0")).as_ptr(),
                    330 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"libc::dup2: %s\0" as *const u8 as *const libc::c_char,
                    strerror(*libc::__errno_location()),
                );
                libc::_exit(1 as libc::c_int);
            }
            close(sv[0 as libc::c_int as usize]);
            close(sv[1 as libc::c_int as usize]);
            crate::misc::replacearg(
                &mut args as *mut arglist,
                0 as libc::c_int as u_int,
                b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                program,
            );
            if port != -(1 as libc::c_int) {
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"-p\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                );
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"%d\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    port,
                );
            }
            if !remuser.is_null() {
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"-l\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                );
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    remuser,
                );
            }
            if subsystem != 0 {
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"-s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                );
            }
            crate::misc::addargs(
                &mut args as *mut arglist,
                b"--\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            );
            crate::misc::addargs(
                &mut args as *mut arglist,
                b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                host,
            );
            crate::misc::addargs(
                &mut args as *mut arglist,
                b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                cmd_0,
            );
            execvp(program, args.list as *const *mut libc::c_char);
            libc::perror(program);
            libc::_exit(1 as libc::c_int);
        }
        _ => {
            close(sv[0 as libc::c_int as usize]);
            *fdin = sv[1 as libc::c_int as usize];
            *fdout = sv[1 as libc::c_int as usize];
            ssh_signal(
                15 as libc::c_int,
                Some(killchild as unsafe extern "C" fn(libc::c_int) -> ()),
            );
            ssh_signal(
                2 as libc::c_int,
                Some(killchild as unsafe extern "C" fn(libc::c_int) -> ()),
            );
            ssh_signal(
                1 as libc::c_int,
                Some(killchild as unsafe extern "C" fn(libc::c_int) -> ()),
            );
            return 0 as libc::c_int;
        }
    };
}
pub unsafe extern "C" fn do_cmd2(
    mut host: *mut libc::c_char,
    mut remuser: *mut libc::c_char,
    mut port: libc::c_int,
    mut cmd_0: *mut libc::c_char,
    mut fdin: libc::c_int,
    mut fdout: libc::c_int,
) -> libc::c_int {
    let mut status: libc::c_int = 0;
    let mut pid: pid_t = 0;
    if verbose_mode != 0 {
        fmprintf(
            stderr,
            b"Executing: 2nd program %s host %s, user %s, command %s\n\0" as *const u8
                as *const libc::c_char,
            ssh_program,
            host,
            if !remuser.is_null() {
                remuser as *const libc::c_char
            } else {
                b"(unspecified)\0" as *const u8 as *const libc::c_char
            },
            cmd_0,
        );
    }
    if port == -(1 as libc::c_int) {
        port = sshport;
    }
    pid = libc::fork();
    if pid == 0 as libc::c_int {
        if libc::dup2(fdin, 0 as libc::c_int) == -(1 as libc::c_int) {
            libc::perror(b"libc::dup2\0" as *const u8 as *const libc::c_char);
        }
        if libc::dup2(fdout, 1 as libc::c_int) == -(1 as libc::c_int) {
            libc::perror(b"libc::dup2\0" as *const u8 as *const libc::c_char);
        }
        crate::misc::replacearg(
            &mut args as *mut arglist,
            0 as libc::c_int as u_int,
            b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            ssh_program,
        );
        if port != -(1 as libc::c_int) {
            crate::misc::addargs(
                &mut args as *mut arglist,
                b"-p\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            );
            crate::misc::addargs(
                &mut args as *mut arglist,
                b"%d\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                port,
            );
        }
        if !remuser.is_null() {
            crate::misc::addargs(
                &mut args as *mut arglist,
                b"-l\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            );
            crate::misc::addargs(
                &mut args as *mut arglist,
                b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                remuser,
            );
        }
        crate::misc::addargs(
            &mut args as *mut arglist,
            b"-oBatchMode=yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        );
        crate::misc::addargs(
            &mut args as *mut arglist,
            b"--\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        );
        crate::misc::addargs(
            &mut args as *mut arglist,
            b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            host,
        );
        crate::misc::addargs(
            &mut args as *mut arglist,
            b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            cmd_0,
        );
        execvp(ssh_program, args.list as *const *mut libc::c_char);
        libc::perror(ssh_program);
        libc::exit(1 as libc::c_int);
    } else if pid == -(1 as libc::c_int) {
        sshfatal(
            b"scp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_cmd2\0")).as_ptr(),
            420 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::fork: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    while libc::waitpid(pid, &mut status, 0 as libc::c_int) == -(1 as libc::c_int) {
        if *libc::__errno_location() != 4 as libc::c_int {
            sshfatal(
                b"scp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_cmd2\0")).as_ptr(),
                424 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"do_cmd2: libc::waitpid: %s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
    }
    return 0 as libc::c_int;
}
pub static mut pwd: *mut libc::passwd = 0 as *const libc::passwd as *mut libc::passwd;
pub static mut userid: uid_t = 0;
pub static mut errs: libc::c_int = 0;
pub static mut remin: libc::c_int = 0;
pub static mut remout: libc::c_int = 0;
pub static mut remin2: libc::c_int = 0;
pub static mut remout2: libc::c_int = 0;
pub static mut Tflag: libc::c_int = 0;
pub static mut pflag: libc::c_int = 0;
pub static mut iamremote: libc::c_int = 0;
pub static mut iamrecursive: libc::c_int = 0;
pub static mut targetshouldbedirectory: libc::c_int = 0;
pub static mut cmd: [libc::c_char; 64] = [0; 64];
pub unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char) -> libc::c_int {
    let mut ch: libc::c_int = 0;
    let mut fflag: libc::c_int = 0;
    let mut tflag: libc::c_int = 0;
    let mut status: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut n: libc::c_int = 0;
    let mut newargv: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut argv0: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut errstr: *const libc::c_char = 0 as *const libc::c_char;
    extern "C" {
        #[link_name = "BSDoptarg"]
        static mut BSDoptarg_0: *mut libc::c_char;
    }
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    let mut mode: scp_mode_e = MODE_SFTP;
    let mut sftp_direct: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut llv: libc::c_longlong = 0;
    crate::misc::sanitise_stdfd();
    msetlocale();
    argv0 = *argv.offset(0 as libc::c_int as isize);
    newargv = xcalloc(
        (if argc + 1 as libc::c_int > 1 as libc::c_int {
            argc + 1 as libc::c_int
        } else {
            1 as libc::c_int
        }) as size_t,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    n = 0 as libc::c_int;
    while n < argc {
        let ref mut fresh0 = *newargv.offset(n as isize);
        *fresh0 = xstrdup(*argv.offset(n as isize));
        n += 1;
        n;
    }
    argv = newargv;
    __progname =
        crate::openbsd_compat::bsd_misc::ssh_get_progname(*argv.offset(0 as libc::c_int as isize));
    log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2 as libc::c_int);
    memset(
        &mut args as *mut arglist as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<arglist>() as libc::c_ulong,
    );
    memset(
        &mut remote_remote_args as *mut arglist as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<arglist>() as libc::c_ulong,
    );
    remote_remote_args.list = 0 as *mut *mut libc::c_char;
    args.list = remote_remote_args.list;
    crate::misc::addargs(
        &mut args as *mut arglist,
        b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        ssh_program,
    );
    crate::misc::addargs(
        &mut args as *mut arglist,
        b"-x\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    crate::misc::addargs(
        &mut args as *mut arglist,
        b"-oPermitLocalCommand=no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    crate::misc::addargs(
        &mut args as *mut arglist,
        b"-oClearAllForwardings=yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    crate::misc::addargs(
        &mut args as *mut arglist,
        b"-oRemoteCommand=none\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    crate::misc::addargs(
        &mut args as *mut arglist,
        b"-oRequestTTY=no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    tflag = 0 as libc::c_int;
    Tflag = tflag;
    fflag = Tflag;
    loop {
        ch = crate::openbsd_compat::getopt_long::BSDgetopt(
            argc,
            argv,
            b"12346ABCTdfOpqRrstvD:F:J:M:P:S:c:i:l:o:X:\0" as *const u8 as *const libc::c_char,
        );
        if !(ch != -(1 as libc::c_int)) {
            break;
        }
        match ch {
            49 => {
                sshfatal(
                    b"scp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    513 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"SSH protocol v.1 is no longer supported\0" as *const u8
                        as *const libc::c_char,
                );
            }
            50 => {}
            65 | 52 | 54 | 67 => {
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"-%c\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    ch,
                );
                crate::misc::addargs(
                    &mut remote_remote_args as *mut arglist,
                    b"-%c\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    ch,
                );
            }
            68 => {
                sftp_direct = BSDoptarg;
            }
            51 => {
                throughlocal = 1 as libc::c_int;
            }
            82 => {
                throughlocal = 0 as libc::c_int;
            }
            111 | 99 | 105 | 70 | 74 => {
                crate::misc::addargs(
                    &mut remote_remote_args as *mut arglist,
                    b"-%c\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    ch,
                );
                crate::misc::addargs(
                    &mut remote_remote_args as *mut arglist,
                    b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    BSDoptarg,
                );
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"-%c\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    ch,
                );
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    BSDoptarg,
                );
            }
            79 => {
                mode = MODE_SCP;
            }
            115 => {
                mode = MODE_SFTP;
            }
            80 => {
                sshport = crate::misc::a2port(BSDoptarg);
                if sshport <= 0 as libc::c_int {
                    sshfatal(
                        b"scp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        553 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"bad port \"%s\"\n\0" as *const u8 as *const libc::c_char,
                        BSDoptarg,
                    );
                }
            }
            66 => {
                crate::misc::addargs(
                    &mut remote_remote_args as *mut arglist,
                    b"-oBatchmode=yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                );
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"-oBatchmode=yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                );
            }
            108 => {
                limit_kbps = crate::openbsd_compat::strtonum::strtonum(
                    BSDoptarg,
                    1 as libc::c_int as libc::c_longlong,
                    (100 as libc::c_int * 1024 as libc::c_int * 1024 as libc::c_int)
                        as libc::c_longlong,
                    &mut errstr,
                );
                if !errstr.is_null() {
                    usage();
                }
                limit_kbps *= 1024 as libc::c_int as libc::c_longlong;
                crate::misc::bandwidth_limit_init(
                    &mut bwlimit,
                    limit_kbps as u_int64_t,
                    16384 as libc::c_int as size_t,
                );
            }
            112 => {
                pflag = 1 as libc::c_int;
            }
            114 => {
                iamrecursive = 1 as libc::c_int;
            }
            83 => {
                ssh_program = xstrdup(BSDoptarg);
            }
            118 => {
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"-v\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                );
                crate::misc::addargs(
                    &mut remote_remote_args as *mut arglist,
                    b"-v\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                );
                if verbose_mode == 0 as libc::c_int {
                    log_level = SYSLOG_LEVEL_DEBUG1;
                } else if (log_level as libc::c_int) < SYSLOG_LEVEL_DEBUG3 as libc::c_int {
                    log_level += 1;
                    log_level;
                }
                verbose_mode = 1 as libc::c_int;
            }
            113 => {
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"-q\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                );
                crate::misc::addargs(
                    &mut remote_remote_args as *mut arglist,
                    b"-q\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                );
                showprogress = 0 as libc::c_int;
            }
            88 => {
                if strncmp(
                    BSDoptarg,
                    b"buffer=\0" as *const u8 as *const libc::c_char,
                    7 as libc::c_int as libc::c_ulong,
                ) == 0 as libc::c_int
                {
                    r = crate::openbsd_compat::fmt_scaled::scan_scaled(BSDoptarg.offset(7 as libc::c_int as isize), &mut llv);
                    if r == 0 as libc::c_int
                        && (llv <= 0 as libc::c_int as libc::c_longlong
                            || llv > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_longlong)
                    {
                        r = -(1 as libc::c_int);
                        *libc::__errno_location() = 22 as libc::c_int;
                    }
                    if r == -(1 as libc::c_int) {
                        sshfatal(
                            b"scp.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            600 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Invalid buffer size \"%s\": %s\0" as *const u8 as *const libc::c_char,
                            BSDoptarg.offset(7 as libc::c_int as isize),
                            strerror(*libc::__errno_location()),
                        );
                    }
                    sftp_copy_buflen = llv as size_t;
                } else if strncmp(
                    BSDoptarg,
                    b"nrequests=\0" as *const u8 as *const libc::c_char,
                    10 as libc::c_int as libc::c_ulong,
                ) == 0 as libc::c_int
                {
                    llv = crate::openbsd_compat::strtonum::strtonum(
                        BSDoptarg.offset(10 as libc::c_int as isize),
                        1 as libc::c_int as libc::c_longlong,
                        (256 as libc::c_int * 1024 as libc::c_int) as libc::c_longlong,
                        &mut errstr,
                    );
                    if !errstr.is_null() {
                        sshfatal(
                            b"scp.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            608 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Invalid number of requests \"%s\": %s\0" as *const u8
                                as *const libc::c_char,
                            BSDoptarg.offset(10 as libc::c_int as isize),
                            errstr,
                        );
                    }
                    sftp_nrequests = llv as size_t;
                } else {
                    sshfatal(
                        b"scp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        612 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Invalid -X option\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            100 => {
                targetshouldbedirectory = 1 as libc::c_int;
            }
            102 => {
                iamremote = 1 as libc::c_int;
                fflag = 1 as libc::c_int;
            }
            116 => {
                iamremote = 1 as libc::c_int;
                tflag = 1 as libc::c_int;
            }
            84 => {
                Tflag = 1 as libc::c_int;
            }
            _ => {
                usage();
            }
        }
    }
    argc -= BSDoptind;
    argv = argv.offset(BSDoptind as isize);
    log_init(argv0, log_level, SYSLOG_FACILITY_USER, 2 as libc::c_int);
    crate::misc::addargs(
        &mut args as *mut arglist,
        b"-oForwardAgent=no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    if iamremote != 0 {
        mode = MODE_SCP;
    }
    userid = libc::getuid();
    pwd = getpwuid(userid);
    if pwd.is_null() {
        sshfatal(
            b"scp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            650 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"unknown user %u\0" as *const u8 as *const libc::c_char,
            userid,
        );
    }
    if isatty(1 as libc::c_int) == 0 {
        showprogress = 0 as libc::c_int;
    }
    if !(pflag != 0) {
        if crate::openbsd_compat::bsd_misc::pledge(
            b"stdio rpath wpath cpath fattr tty proc exec\0" as *const u8 as *const libc::c_char,
            0 as *mut *const libc::c_char,
        ) == -(1 as libc::c_int)
        {
            libc::perror(
                b"crate::openbsd_compat::bsd_misc::pledge\0" as *const u8 as *const libc::c_char,
            );
            libc::exit(1 as libc::c_int);
        }
    }
    remin = 0 as libc::c_int;
    remout = 1 as libc::c_int;
    if fflag != 0 {
        response();
        source(argc, argv);
        libc::exit((errs != 0 as libc::c_int) as libc::c_int);
    }
    if tflag != 0 {
        sink(argc, argv, 0 as *const libc::c_char);
        libc::exit((errs != 0 as libc::c_int) as libc::c_int);
    }
    if argc < 2 as libc::c_int {
        usage();
    }
    if argc > 2 as libc::c_int {
        targetshouldbedirectory = 1 as libc::c_int;
    }
    remout = -(1 as libc::c_int);
    remin = remout;
    do_cmd_pid = -(1 as libc::c_int);
    libc::snprintf(
        cmd.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 64]>() as usize,
        b"scp%s%s%s%s\0" as *const u8 as *const libc::c_char,
        if verbose_mode != 0 {
            b" -v\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if iamrecursive != 0 {
            b" -r\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if pflag != 0 {
            b" -p\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if targetshouldbedirectory != 0 {
            b" -d\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    ssh_signal(
        13 as libc::c_int,
        Some(lostconn as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    if !(colon(*argv.offset((argc - 1 as libc::c_int) as isize))).is_null() {
        toremote(argc, argv, mode, sftp_direct);
    } else {
        if targetshouldbedirectory != 0 {
            verifydir(*argv.offset((argc - 1 as libc::c_int) as isize));
        }
        tolocal(argc, argv, mode, sftp_direct);
    }
    if do_cmd_pid != -(1 as libc::c_int)
        && (mode as libc::c_uint == MODE_SFTP as libc::c_int as libc::c_uint
            || errs == 0 as libc::c_int)
    {
        if remin != -(1 as libc::c_int) {
            close(remin);
        }
        if remout != -(1 as libc::c_int) {
            close(remout);
        }
        if libc::waitpid(do_cmd_pid, &mut status, 0 as libc::c_int) == -(1 as libc::c_int) {
            errs = 1 as libc::c_int;
        } else if !(status & 0x7f as libc::c_int == 0 as libc::c_int)
            || (status & 0xff00 as libc::c_int) >> 8 as libc::c_int != 0 as libc::c_int
        {
            errs = 1 as libc::c_int;
        }
    }
    libc::exit((errs != 0 as libc::c_int) as libc::c_int);
}
unsafe extern "C" fn scpio(mut _cnt: *mut libc::c_void, mut s: size_t) -> libc::c_int {
    let mut cnt: *mut off_t = _cnt as *mut off_t;
    *cnt = (*cnt as libc::c_ulong).wrapping_add(s) as off_t as off_t;
    refresh_progress_meter(0 as libc::c_int);
    if limit_kbps > 0 as libc::c_int as libc::c_longlong {
        crate::misc::bandwidth_limit(&mut bwlimit, s);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn do_times(
    mut fd: libc::c_int,
    mut verb: libc::c_int,
    mut sb: *const libc::stat,
) -> libc::c_int {
    let mut buf: [libc::c_char; 60] = [0; 60];
    libc::snprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 60]>() as usize,
        b"T%llu 0 %llu 0\n\0" as *const u8 as *const libc::c_char,
        (if (*sb).st_mtime < 0 as libc::c_int as libc::c_long {
            0 as libc::c_int as libc::c_long
        } else {
            (*sb).st_mtime
        }) as libc::c_ulonglong,
        (if (*sb).st_atime < 0 as libc::c_int as libc::c_long {
            0 as libc::c_int as libc::c_long
        } else {
            (*sb).st_atime
        }) as libc::c_ulonglong,
    );
    if verb != 0 {
        libc::fprintf(
            stderr,
            b"File mtime %lld atime %lld\n\0" as *const u8 as *const libc::c_char,
            (*sb).st_mtime as libc::c_longlong,
            (*sb).st_atime as libc::c_longlong,
        );
        libc::fprintf(
            stderr,
            b"Sending file timestamps: %s\0" as *const u8 as *const libc::c_char,
            buf.as_mut_ptr(),
        );
    }
    atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        fd,
        buf.as_mut_ptr() as *mut libc::c_void,
        strlen(buf.as_mut_ptr()),
    );
    return response();
}
unsafe extern "C" fn parse_scp_uri(
    mut uri: *const libc::c_char,
    mut userp: *mut *mut libc::c_char,
    mut hostp: *mut *mut libc::c_char,
    mut portp: *mut libc::c_int,
    mut pathp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = parse_uri(
        b"scp\0" as *const u8 as *const libc::c_char,
        uri,
        userp,
        hostp,
        portp,
        pathp,
    );
    if r == 0 as libc::c_int && (*pathp).is_null() {
        *pathp = xstrdup(b".\0" as *const u8 as *const libc::c_char);
    }
    return r;
}
unsafe extern "C" fn append(
    mut cp: *mut libc::c_char,
    mut ap: *mut *mut *mut libc::c_char,
    mut np: *mut size_t,
) -> libc::c_int {
    let mut tmp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    tmp = reallocarray(
        *ap as *mut libc::c_void,
        (*np).wrapping_add(1 as libc::c_int as libc::c_ulong),
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    if tmp.is_null() {
        return -(1 as libc::c_int);
    }
    let ref mut fresh1 = *tmp.offset(*np as isize);
    *fresh1 = cp;
    *np = (*np).wrapping_add(1);
    *np;
    *ap = tmp;
    return 0 as libc::c_int;
}
unsafe extern "C" fn find_brace(
    mut pattern: *const libc::c_char,
    mut startp: *mut libc::c_int,
    mut endp: *mut libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut in_bracket: libc::c_int = 0;
    let mut brace_level: libc::c_int = 0;
    *endp = -(1 as libc::c_int);
    *startp = *endp;
    brace_level = 0 as libc::c_int;
    in_bracket = brace_level;
    i = 0 as libc::c_int;
    while i < 2147483647 as libc::c_int
        && *endp < 0 as libc::c_int
        && *pattern.offset(i as isize) as libc::c_int != '\0' as i32
    {
        match *pattern.offset(i as isize) as libc::c_int {
            92 => {
                if *pattern.offset((i + 1 as libc::c_int) as isize) as libc::c_int != '\0' as i32 {
                    i += 1;
                    i;
                }
            }
            91 => {
                in_bracket = 1 as libc::c_int;
            }
            93 => {
                in_bracket = 0 as libc::c_int;
            }
            123 => {
                if !(in_bracket != 0) {
                    if *pattern.offset((i + 1 as libc::c_int) as isize) as libc::c_int == '}' as i32
                    {
                        i += 1;
                        i;
                    } else {
                        if *startp == -(1 as libc::c_int) {
                            *startp = i;
                        }
                        brace_level += 1;
                        brace_level;
                    }
                }
            }
            125 => {
                if !(in_bracket != 0) {
                    if *startp < 0 as libc::c_int {
                        return -(1 as libc::c_int);
                    }
                    brace_level -= 1;
                    if brace_level <= 0 as libc::c_int {
                        *endp = i;
                    }
                }
            }
            _ => {}
        }
        i += 1;
        i;
    }
    if *endp < 0 as libc::c_int && (*startp >= 0 as libc::c_int || in_bracket != 0) {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn emit_expansion(
    mut pattern: *const libc::c_char,
    mut brace_start: libc::c_int,
    mut brace_end: libc::c_int,
    mut sel_start: libc::c_int,
    mut sel_end: libc::c_int,
    mut patternsp: *mut *mut *mut libc::c_char,
    mut npatternsp: *mut size_t,
) -> libc::c_int {
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut o: libc::c_int = 0 as libc::c_int;
    let mut tail_len: libc::c_int = strlen(
        pattern
            .offset(brace_end as isize)
            .offset(1 as libc::c_int as isize),
    ) as libc::c_int;
    cp = libc::malloc((brace_start + (sel_end - sel_start) + tail_len + 1 as libc::c_int) as usize)
        as *mut libc::c_char;
    if cp.is_null() {
        return -(1 as libc::c_int);
    }
    if brace_start > 0 as libc::c_int {
        memcpy(
            cp as *mut libc::c_void,
            pattern as *const libc::c_void,
            brace_start as libc::c_ulong,
        );
        o = brace_start;
    }
    if sel_end - sel_start > 0 as libc::c_int {
        memcpy(
            cp.offset(o as isize) as *mut libc::c_void,
            pattern.offset(sel_start as isize) as *const libc::c_void,
            (sel_end - sel_start) as libc::c_ulong,
        );
        o += sel_end - sel_start;
    }
    if tail_len > 0 as libc::c_int {
        memcpy(
            cp.offset(o as isize) as *mut libc::c_void,
            pattern
                .offset(brace_end as isize)
                .offset(1 as libc::c_int as isize) as *const libc::c_void,
            tail_len as libc::c_ulong,
        );
        o += tail_len;
    }
    *cp.offset(o as isize) = '\0' as i32 as libc::c_char;
    if append(cp, patternsp, npatternsp) != 0 as libc::c_int {
        libc::free(cp as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn brace_expand_one(
    mut pattern: *const libc::c_char,
    mut patternsp: *mut *mut *mut libc::c_char,
    mut npatternsp: *mut size_t,
    mut expanded: *mut libc::c_int,
    mut invalid: *mut libc::c_int,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut in_bracket: libc::c_int = 0;
    let mut brace_start: libc::c_int = 0;
    let mut brace_end: libc::c_int = 0;
    let mut brace_level: libc::c_int = 0;
    let mut sel_start: libc::c_int = 0;
    let mut sel_end: libc::c_int = 0;
    *expanded = 0 as libc::c_int;
    *invalid = *expanded;
    if find_brace(pattern, &mut brace_start, &mut brace_end) != 0 as libc::c_int {
        *invalid = 1 as libc::c_int;
        return 0 as libc::c_int;
    } else if brace_start == -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    brace_level = 0 as libc::c_int;
    in_bracket = brace_level;
    sel_start = brace_start + 1 as libc::c_int;
    i = sel_start;
    while i < brace_end {
        match *pattern.offset(i as isize) as libc::c_int {
            123 => {
                if !(in_bracket != 0) {
                    brace_level += 1;
                    brace_level;
                }
            }
            125 => {
                if !(in_bracket != 0) {
                    brace_level -= 1;
                    brace_level;
                }
            }
            91 => {
                in_bracket = 1 as libc::c_int;
            }
            93 => {
                in_bracket = 0 as libc::c_int;
            }
            92 => {
                if i < brace_end - 1 as libc::c_int {
                    i += 1;
                    i;
                }
            }
            _ => {}
        }
        if *pattern.offset(i as isize) as libc::c_int == ',' as i32
            || i == brace_end - 1 as libc::c_int
        {
            if !(in_bracket != 0 || brace_level > 0 as libc::c_int) {
                sel_end = if i == brace_end - 1 as libc::c_int {
                    brace_end
                } else {
                    i
                };
                if emit_expansion(
                    pattern,
                    brace_start,
                    brace_end,
                    sel_start,
                    sel_end,
                    patternsp,
                    npatternsp,
                ) != 0 as libc::c_int
                {
                    return -(1 as libc::c_int);
                }
                sel_start = i + 1 as libc::c_int;
            }
        }
        i += 1;
        i;
    }
    if in_bracket != 0 || brace_level > 0 as libc::c_int {
        *invalid = 1 as libc::c_int;
        return 0 as libc::c_int;
    }
    *expanded = 1 as libc::c_int;
    return 0 as libc::c_int;
}
unsafe extern "C" fn brace_expand(
    mut pattern: *const libc::c_char,
    mut patternsp: *mut *mut *mut libc::c_char,
    mut npatternsp: *mut size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp2: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut active: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut done: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut i: size_t = 0;
    let mut nactive: size_t = 0 as libc::c_int as size_t;
    let mut ndone: size_t = 0 as libc::c_int as size_t;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut invalid: libc::c_int = 0 as libc::c_int;
    let mut expanded: libc::c_int = 0 as libc::c_int;
    *patternsp = 0 as *mut *mut libc::c_char;
    *npatternsp = 0 as libc::c_int as size_t;
    cp = strdup(pattern);
    if cp.is_null() {
        return -(1 as libc::c_int);
    }
    if append(cp, &mut active, &mut nactive) != 0 as libc::c_int {
        libc::free(cp as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    loop {
        if !(nactive > 0 as libc::c_int as libc::c_ulong) {
            current_block = 7175849428784450219;
            break;
        }
        cp = *active.offset(nactive.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize);
        nactive = nactive.wrapping_sub(1);
        nactive;
        if brace_expand_one(cp, &mut active, &mut nactive, &mut expanded, &mut invalid)
            == -(1 as libc::c_int)
        {
            libc::free(cp as *mut libc::c_void);
            current_block = 13913881577436039028;
            break;
        } else {
            if invalid != 0 {
                sshfatal(
                    b"scp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"brace_expand\0"))
                        .as_ptr(),
                    971 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"invalid brace pattern \"%s\"\0" as *const u8 as *const libc::c_char,
                    cp,
                );
            }
            if expanded != 0 {
                libc::free(cp as *mut libc::c_void);
            } else {
                cp2 = strrchr(cp, '/' as i32);
                if !cp2.is_null() {
                    let fresh2 = cp2;
                    cp2 = cp2.offset(1);
                    *fresh2 = '\0' as i32 as libc::c_char;
                } else {
                    cp2 = cp;
                }
                if append(xstrdup(cp2), &mut done, &mut ndone) != 0 as libc::c_int {
                    libc::free(cp as *mut libc::c_void);
                    current_block = 13913881577436039028;
                    break;
                } else {
                    libc::free(cp as *mut libc::c_void);
                }
            }
        }
    }
    match current_block {
        7175849428784450219 => {
            *patternsp = done;
            *npatternsp = ndone;
            done = 0 as *mut *mut libc::c_char;
            ndone = 0 as libc::c_int as size_t;
            ret = 0 as libc::c_int;
        }
        _ => {}
    }
    i = 0 as libc::c_int as size_t;
    while i < nactive {
        libc::free(*active.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free(active as *mut libc::c_void);
    i = 0 as libc::c_int as size_t;
    while i < ndone {
        libc::free(*done.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free(done as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn do_sftp_connect(
    mut host: *mut libc::c_char,
    mut user: *mut libc::c_char,
    mut port: libc::c_int,
    mut sftp_direct: *mut libc::c_char,
    mut reminp: *mut libc::c_int,
    mut remoutp: *mut libc::c_int,
    mut pidp: *mut libc::c_int,
) -> *mut sftp_conn {
    if sftp_direct.is_null() {
        if do_cmd(
            ssh_program,
            host,
            user,
            port,
            1 as libc::c_int,
            b"sftp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            reminp,
            remoutp,
            pidp,
        ) < 0 as libc::c_int
        {
            return 0 as *mut sftp_conn;
        }
    } else {
        crate::misc::freeargs(&mut args);
        crate::misc::addargs(
            &mut args as *mut arglist,
            b"sftp-server\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        );
        if do_cmd(
            sftp_direct,
            host,
            0 as *mut libc::c_char,
            -(1 as libc::c_int),
            0 as libc::c_int,
            b"sftp\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            reminp,
            remoutp,
            pidp,
        ) < 0 as libc::c_int
        {
            return 0 as *mut sftp_conn;
        }
    }
    return do_init(
        *reminp,
        *remoutp,
        sftp_copy_buflen as u_int,
        sftp_nrequests as u_int,
        limit_kbps as u_int64_t,
    );
}
pub unsafe extern "C" fn toremote(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
    mut mode: scp_mode_e,
    mut sftp_direct: *mut libc::c_char,
) {
    let mut current_block: u64;
    let mut suser: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut src: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut bp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tuser: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut thost: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut targ: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sport: libc::c_int = -(1 as libc::c_int);
    let mut tport: libc::c_int = -(1 as libc::c_int);
    let mut conn: *mut sftp_conn = 0 as *mut sftp_conn;
    let mut conn2: *mut sftp_conn = 0 as *mut sftp_conn;
    let mut alist: arglist = arglist {
        list: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
        num: 0,
        nalloc: 0,
    };
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 0;
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    let mut j: u_int = 0;
    memset(
        &mut alist as *mut arglist as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<arglist>() as libc::c_ulong,
    );
    alist.list = 0 as *mut *mut libc::c_char;
    r = parse_scp_uri(
        *argv.offset((argc - 1 as libc::c_int) as isize),
        &mut tuser,
        &mut thost,
        &mut tport,
        &mut targ,
    );
    if r == -(1 as libc::c_int) {
        fmprintf(
            stderr,
            b"%s: invalid uri\n\0" as *const u8 as *const libc::c_char,
            *argv.offset((argc - 1 as libc::c_int) as isize),
        );
        errs += 1;
        errs;
    } else {
        if r != 0 as libc::c_int {
            if parse_user_host_path(
                *argv.offset((argc - 1 as libc::c_int) as isize),
                &mut tuser,
                &mut thost,
                &mut targ,
            ) == -(1 as libc::c_int)
            {
                fmprintf(
                    stderr,
                    b"%s: invalid target\n\0" as *const u8 as *const libc::c_char,
                    *argv.offset((argc - 1 as libc::c_int) as isize),
                );
                errs += 1;
                errs;
                current_block = 4531405220720023016;
            } else {
                current_block = 7746791466490516765;
            }
        } else {
            current_block = 7746791466490516765;
        }
        match current_block {
            4531405220720023016 => {}
            _ => {
                i = 0 as libc::c_int;
                while i < argc - 1 as libc::c_int {
                    libc::free(suser as *mut libc::c_void);
                    libc::free(host as *mut libc::c_void);
                    libc::free(src as *mut libc::c_void);
                    r = parse_scp_uri(
                        *argv.offset(i as isize),
                        &mut suser,
                        &mut host,
                        &mut sport,
                        &mut src,
                    );
                    if r == -(1 as libc::c_int) {
                        fmprintf(
                            stderr,
                            b"%s: invalid uri\n\0" as *const u8 as *const libc::c_char,
                            *argv.offset(i as isize),
                        );
                        errs += 1;
                        errs;
                    } else {
                        if r != 0 as libc::c_int {
                            parse_user_host_path(
                                *argv.offset(i as isize),
                                &mut suser,
                                &mut host,
                                &mut src,
                            );
                        }
                        if !suser.is_null() && okname(suser) == 0 {
                            errs += 1;
                            errs;
                        } else if !host.is_null() && throughlocal != 0 {
                            if mode as libc::c_uint == MODE_SFTP as libc::c_int as libc::c_uint {
                                if remin == -(1 as libc::c_int) {
                                    conn = do_sftp_connect(
                                        thost,
                                        tuser,
                                        tport,
                                        sftp_direct,
                                        &mut remin,
                                        &mut remout,
                                        &mut do_cmd_pid,
                                    );
                                    if conn.is_null() {
                                        sshfatal(
                                            b"scp.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 9],
                                                &[libc::c_char; 9],
                                            >(b"toremote\0"))
                                                .as_ptr(),
                                            1088 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_FATAL,
                                            0 as *const libc::c_char,
                                            b"Unable to open destination connection\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                    }
                                    crate::log::sshlog(
                                        b"scp.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(
                                            b"toremote\0",
                                        ))
                                        .as_ptr(),
                                        1091 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG3,
                                        0 as *const libc::c_char,
                                        b"origin in %d out %d pid %ld\0" as *const u8
                                            as *const libc::c_char,
                                        remin,
                                        remout,
                                        do_cmd_pid as libc::c_long,
                                    );
                                }
                                conn2 = do_sftp_connect(
                                    host,
                                    suser,
                                    sport,
                                    sftp_direct,
                                    &mut remin2,
                                    &mut remout2,
                                    &mut do_cmd_pid2,
                                );
                                if conn2.is_null() {
                                    sshfatal(
                                        b"scp.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(
                                            b"toremote\0",
                                        ))
                                        .as_ptr(),
                                        1105 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_FATAL,
                                        0 as *const libc::c_char,
                                        b"Unable to open source connection\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                }
                                crate::log::sshlog(
                                    b"scp.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(
                                        b"toremote\0",
                                    ))
                                    .as_ptr(),
                                    1108 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG3,
                                    0 as *const libc::c_char,
                                    b"destination in %d out %d pid %ld\0" as *const u8
                                        as *const libc::c_char,
                                    remin2,
                                    remout2,
                                    do_cmd_pid2 as libc::c_long,
                                );
                                throughlocal_sftp(conn2, conn, src, targ);
                                close(remin2);
                                close(remout2);
                                remout2 = -(1 as libc::c_int);
                                remin2 = remout2;
                                if libc::waitpid(do_cmd_pid2, &mut status, 0 as libc::c_int)
                                    == -(1 as libc::c_int)
                                {
                                    errs += 1;
                                    errs;
                                } else if !(status & 0x7f as libc::c_int == 0 as libc::c_int)
                                    || (status & 0xff00 as libc::c_int) >> 8 as libc::c_int
                                        != 0 as libc::c_int
                                {
                                    errs += 1;
                                    errs;
                                }
                                do_cmd_pid2 = -(1 as libc::c_int);
                            } else {
                                xasprintf(
                                    &mut bp as *mut *mut libc::c_char,
                                    b"%s -f %s%s\0" as *const u8 as *const libc::c_char,
                                    cmd.as_mut_ptr(),
                                    if *src as libc::c_int == '-' as i32 {
                                        b"-- \0" as *const u8 as *const libc::c_char
                                    } else {
                                        b"\0" as *const u8 as *const libc::c_char
                                    },
                                    src,
                                );
                                if do_cmd(
                                    ssh_program,
                                    host,
                                    suser,
                                    sport,
                                    0 as libc::c_int,
                                    bp,
                                    &mut remin,
                                    &mut remout,
                                    &mut do_cmd_pid,
                                ) < 0 as libc::c_int
                                {
                                    libc::exit(1 as libc::c_int);
                                }
                                libc::free(bp as *mut libc::c_void);
                                xasprintf(
                                    &mut bp as *mut *mut libc::c_char,
                                    b"%s -t %s%s\0" as *const u8 as *const libc::c_char,
                                    cmd.as_mut_ptr(),
                                    if *targ as libc::c_int == '-' as i32 {
                                        b"-- \0" as *const u8 as *const libc::c_char
                                    } else {
                                        b"\0" as *const u8 as *const libc::c_char
                                    },
                                    targ,
                                );
                                if do_cmd2(thost, tuser, tport, bp, remin, remout)
                                    < 0 as libc::c_int
                                {
                                    libc::exit(1 as libc::c_int);
                                }
                                libc::free(bp as *mut libc::c_void);
                                close(remin);
                                close(remout);
                                remout = -(1 as libc::c_int);
                                remin = remout;
                            }
                        } else if !host.is_null() {
                            if !tuser.is_null() && okname(tuser) == 0 {
                                errs += 1;
                                errs;
                            } else {
                                if tport != -(1 as libc::c_int) && tport != 22 as libc::c_int {
                                    sshfatal(
                                        b"scp.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<
                                            &[u8; 9],
                                            &[libc::c_char; 9],
                                        >(b"toremote\0"))
                                            .as_ptr(),
                                        1150 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_FATAL,
                                        0 as *const libc::c_char,
                                        b"target port not supported with two remote hosts and the -R option\0"
                                            as *const u8 as *const libc::c_char,
                                    );
                                }
                                crate::misc::freeargs(&mut alist);
                                crate::misc::addargs(
                                    &mut alist as *mut arglist,
                                    b"%s\0" as *const u8 as *const libc::c_char
                                        as *mut libc::c_char,
                                    ssh_program,
                                );
                                crate::misc::addargs(
                                    &mut alist as *mut arglist,
                                    b"-x\0" as *const u8 as *const libc::c_char
                                        as *mut libc::c_char,
                                );
                                crate::misc::addargs(
                                    &mut alist as *mut arglist,
                                    b"-oClearAllForwardings=yes\0" as *const u8
                                        as *const libc::c_char
                                        as *mut libc::c_char,
                                );
                                crate::misc::addargs(
                                    &mut alist as *mut arglist,
                                    b"-n\0" as *const u8 as *const libc::c_char
                                        as *mut libc::c_char,
                                );
                                j = 0 as libc::c_int as u_int;
                                while j < remote_remote_args.num {
                                    crate::misc::addargs(
                                        &mut alist as *mut arglist,
                                        b"%s\0" as *const u8 as *const libc::c_char
                                            as *mut libc::c_char,
                                        *(remote_remote_args.list).offset(j as isize),
                                    );
                                    j = j.wrapping_add(1);
                                    j;
                                }
                                if sport != -(1 as libc::c_int) {
                                    crate::misc::addargs(
                                        &mut alist as *mut arglist,
                                        b"-p\0" as *const u8 as *const libc::c_char
                                            as *mut libc::c_char,
                                    );
                                    crate::misc::addargs(
                                        &mut alist as *mut arglist,
                                        b"%d\0" as *const u8 as *const libc::c_char
                                            as *mut libc::c_char,
                                        sport,
                                    );
                                }
                                if !suser.is_null() {
                                    crate::misc::addargs(
                                        &mut alist as *mut arglist,
                                        b"-l\0" as *const u8 as *const libc::c_char
                                            as *mut libc::c_char,
                                    );
                                    crate::misc::addargs(
                                        &mut alist as *mut arglist,
                                        b"%s\0" as *const u8 as *const libc::c_char
                                            as *mut libc::c_char,
                                        suser,
                                    );
                                }
                                crate::misc::addargs(
                                    &mut alist as *mut arglist,
                                    b"--\0" as *const u8 as *const libc::c_char
                                        as *mut libc::c_char,
                                );
                                crate::misc::addargs(
                                    &mut alist as *mut arglist,
                                    b"%s\0" as *const u8 as *const libc::c_char
                                        as *mut libc::c_char,
                                    host,
                                );
                                crate::misc::addargs(
                                    &mut alist as *mut arglist,
                                    b"%s\0" as *const u8 as *const libc::c_char
                                        as *mut libc::c_char,
                                    cmd.as_mut_ptr(),
                                );
                                crate::misc::addargs(
                                    &mut alist as *mut arglist,
                                    b"%s\0" as *const u8 as *const libc::c_char
                                        as *mut libc::c_char,
                                    src,
                                );
                                crate::misc::addargs(
                                    &mut alist as *mut arglist,
                                    b"%s%s%s:%s\0" as *const u8 as *const libc::c_char
                                        as *mut libc::c_char,
                                    if !tuser.is_null() {
                                        tuser as *const libc::c_char
                                    } else {
                                        b"\0" as *const u8 as *const libc::c_char
                                    },
                                    if !tuser.is_null() {
                                        b"@\0" as *const u8 as *const libc::c_char
                                    } else {
                                        b"\0" as *const u8 as *const libc::c_char
                                    },
                                    thost,
                                    targ,
                                );
                                if do_local_cmd(&mut alist) != 0 as libc::c_int {
                                    errs = 1 as libc::c_int;
                                }
                            }
                        } else if mode as libc::c_uint == MODE_SFTP as libc::c_int as libc::c_uint {
                            if libc::stat(*argv.offset(i as isize), &mut sb) != 0 as libc::c_int {
                                sshfatal(
                                    b"scp.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(
                                        b"toremote\0",
                                    ))
                                    .as_ptr(),
                                    1185 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    0 as *const libc::c_char,
                                    b"libc::stat local \"%s\": %s\0" as *const u8
                                        as *const libc::c_char,
                                    *argv.offset(i as isize),
                                    strerror(*libc::__errno_location()),
                                );
                            }
                            if remin == -(1 as libc::c_int) {
                                conn = do_sftp_connect(
                                    thost,
                                    tuser,
                                    tport,
                                    sftp_direct,
                                    &mut remin,
                                    &mut remout,
                                    &mut do_cmd_pid,
                                );
                                if conn.is_null() {
                                    sshfatal(
                                        b"scp.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(
                                            b"toremote\0",
                                        ))
                                        .as_ptr(),
                                        1194 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_FATAL,
                                        0 as *const libc::c_char,
                                        b"Unable to open sftp connection\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                }
                            }
                            source_sftp(1 as libc::c_int, *argv.offset(i as isize), targ, conn);
                        } else {
                            if remin == -(1 as libc::c_int) {
                                xasprintf(
                                    &mut bp as *mut *mut libc::c_char,
                                    b"%s -t %s%s\0" as *const u8 as *const libc::c_char,
                                    cmd.as_mut_ptr(),
                                    if *targ as libc::c_int == '-' as i32 {
                                        b"-- \0" as *const u8 as *const libc::c_char
                                    } else {
                                        b"\0" as *const u8 as *const libc::c_char
                                    },
                                    targ,
                                );
                                if do_cmd(
                                    ssh_program,
                                    thost,
                                    tuser,
                                    tport,
                                    0 as libc::c_int,
                                    bp,
                                    &mut remin,
                                    &mut remout,
                                    &mut do_cmd_pid,
                                ) < 0 as libc::c_int
                                {
                                    libc::exit(1 as libc::c_int);
                                }
                                if response() < 0 as libc::c_int {
                                    libc::exit(1 as libc::c_int);
                                }
                                libc::free(bp as *mut libc::c_void);
                            }
                            source(1 as libc::c_int, argv.offset(i as isize));
                        }
                    }
                    i += 1;
                    i;
                }
            }
        }
    }
    if mode as libc::c_uint == MODE_SFTP as libc::c_int as libc::c_uint {
        libc::free(conn as *mut libc::c_void);
    }
    libc::free(tuser as *mut libc::c_void);
    libc::free(thost as *mut libc::c_void);
    libc::free(targ as *mut libc::c_void);
    libc::free(suser as *mut libc::c_void);
    libc::free(host as *mut libc::c_void);
    libc::free(src as *mut libc::c_void);
}
pub unsafe extern "C" fn tolocal(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
    mut mode: scp_mode_e,
    mut sftp_direct: *mut libc::c_char,
) {
    let mut bp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut src: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut suser: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut alist: arglist = arglist {
        list: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
        num: 0,
        nalloc: 0,
    };
    let mut conn: *mut sftp_conn = 0 as *mut sftp_conn;
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut sport: libc::c_int = -(1 as libc::c_int);
    memset(
        &mut alist as *mut arglist as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<arglist>() as libc::c_ulong,
    );
    alist.list = 0 as *mut *mut libc::c_char;
    i = 0 as libc::c_int;
    while i < argc - 1 as libc::c_int {
        libc::free(suser as *mut libc::c_void);
        libc::free(host as *mut libc::c_void);
        libc::free(src as *mut libc::c_void);
        r = parse_scp_uri(
            *argv.offset(i as isize),
            &mut suser,
            &mut host,
            &mut sport,
            &mut src,
        );
        if r == -(1 as libc::c_int) {
            fmprintf(
                stderr,
                b"%s: invalid uri\n\0" as *const u8 as *const libc::c_char,
                *argv.offset(i as isize),
            );
            errs += 1;
            errs;
        } else {
            if r != 0 as libc::c_int {
                parse_user_host_path(*argv.offset(i as isize), &mut suser, &mut host, &mut src);
            }
            if !suser.is_null() && okname(suser) == 0 {
                errs += 1;
                errs;
            } else if host.is_null() {
                crate::misc::freeargs(&mut alist);
                crate::misc::addargs(
                    &mut alist as *mut arglist,
                    b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    b"cp\0" as *const u8 as *const libc::c_char,
                );
                if iamrecursive != 0 {
                    crate::misc::addargs(
                        &mut alist as *mut arglist,
                        b"-r\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    );
                }
                if pflag != 0 {
                    crate::misc::addargs(
                        &mut alist as *mut arglist,
                        b"-p\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    );
                }
                crate::misc::addargs(
                    &mut alist as *mut arglist,
                    b"--\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                );
                crate::misc::addargs(
                    &mut alist as *mut arglist,
                    b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    *argv.offset(i as isize),
                );
                crate::misc::addargs(
                    &mut alist as *mut arglist,
                    b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    *argv.offset((argc - 1 as libc::c_int) as isize),
                );
                if do_local_cmd(&mut alist) != 0 {
                    errs += 1;
                    errs;
                }
            } else if mode as libc::c_uint == MODE_SFTP as libc::c_int as libc::c_uint {
                conn = do_sftp_connect(
                    host,
                    suser,
                    sport,
                    sftp_direct,
                    &mut remin,
                    &mut remout,
                    &mut do_cmd_pid,
                );
                if conn.is_null() {
                    crate::log::sshlog(
                        b"scp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"tolocal\0"))
                            .as_ptr(),
                        1273 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"sftp connection failed\0" as *const u8 as *const libc::c_char,
                    );
                    errs += 1;
                    errs;
                } else {
                    sink_sftp(
                        1 as libc::c_int,
                        *argv.offset((argc - 1 as libc::c_int) as isize),
                        src,
                        conn,
                    );
                    libc::free(conn as *mut libc::c_void);
                    close(remin);
                    close(remout);
                    remout = -(1 as libc::c_int);
                    remin = remout;
                }
            } else {
                xasprintf(
                    &mut bp as *mut *mut libc::c_char,
                    b"%s -f %s%s\0" as *const u8 as *const libc::c_char,
                    cmd.as_mut_ptr(),
                    if *src as libc::c_int == '-' as i32 {
                        b"-- \0" as *const u8 as *const libc::c_char
                    } else {
                        b"\0" as *const u8 as *const libc::c_char
                    },
                    src,
                );
                if do_cmd(
                    ssh_program,
                    host,
                    suser,
                    sport,
                    0 as libc::c_int,
                    bp,
                    &mut remin,
                    &mut remout,
                    &mut do_cmd_pid,
                ) < 0 as libc::c_int
                {
                    libc::free(bp as *mut libc::c_void);
                    errs += 1;
                    errs;
                } else {
                    libc::free(bp as *mut libc::c_void);
                    sink(
                        1 as libc::c_int,
                        argv.offset(argc as isize)
                            .offset(-(1 as libc::c_int as isize)),
                        src,
                    );
                    close(remin);
                    remout = -(1 as libc::c_int);
                    remin = remout;
                }
            }
        }
        i += 1;
        i;
    }
    libc::free(suser as *mut libc::c_void);
    libc::free(host as *mut libc::c_void);
    libc::free(src as *mut libc::c_void);
}
unsafe extern "C" fn prepare_remote_path(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
) -> *mut libc::c_char {
    let mut nslash: size_t = 0;
    if *path as libc::c_int == '\0' as i32
        || strcmp(path, b"~\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        return xstrdup(b".\0" as *const u8 as *const libc::c_char);
    }
    if *path as libc::c_int != '~' as i32 {
        return xstrdup(path);
    }
    if strncmp(
        path,
        b"~/\0" as *const u8 as *const libc::c_char,
        2 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
    {
        nslash = strspn(
            path.offset(2 as libc::c_int as isize),
            b"/\0" as *const u8 as *const libc::c_char,
        );
        if nslash == strlen(path.offset(2 as libc::c_int as isize)) {
            return xstrdup(b".\0" as *const u8 as *const libc::c_char);
        }
        return xstrdup(
            path.offset(2 as libc::c_int as isize)
                .offset(nslash as isize),
        );
    }
    if can_expand_path(conn) != 0 {
        return do_expand_path(conn, path);
    }
    crate::log::sshlog(
        b"scp.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"prepare_remote_path\0"))
            .as_ptr(),
        1326 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"server expand-path extension is required for ~user paths in SFTP mode\0" as *const u8
            as *const libc::c_char,
    );
    return 0 as *mut libc::c_char;
}
pub unsafe extern "C" fn source_sftp(
    mut _argc: libc::c_int,
    mut src: *mut libc::c_char,
    mut targ: *mut libc::c_char,
    mut conn: *mut sftp_conn,
) {
    let mut target: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut abs_dst: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut src_is_dir: libc::c_int = 0;
    let mut target_is_dir: libc::c_int = 0;
    let mut a: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    memset(
        &mut a as *mut Attrib as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<Attrib>() as libc::c_ulong,
    );
    if libc::stat(src, &mut st) != 0 as libc::c_int {
        sshfatal(
            b"scp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"source_sftp\0")).as_ptr(),
            1340 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::stat local \"%s\": %s\0" as *const u8 as *const libc::c_char,
            src,
            strerror(*libc::__errno_location()),
        );
    }
    src_is_dir = (st.st_mode & 0o170000 as libc::c_int as libc::c_uint
        == 0o40000 as libc::c_int as libc::c_uint) as libc::c_int;
    filename = __xpg_basename(src);
    if filename.is_null() {
        sshfatal(
            b"scp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"source_sftp\0")).as_ptr(),
            1343 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"basename \"%s\": %s\0" as *const u8 as *const libc::c_char,
            src,
            strerror(*libc::__errno_location()),
        );
    }
    target = prepare_remote_path(conn, targ);
    if target.is_null() {
        cleanup_exit(255 as libc::c_int);
    }
    target_is_dir = remote_is_dir(conn, target);
    if targetshouldbedirectory != 0 && target_is_dir == 0 {
        crate::log::sshlog(
            b"scp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"source_sftp\0")).as_ptr(),
            1353 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"target directory \"%s\" does not exist\0" as *const u8 as *const libc::c_char,
            target,
        );
        a.flags = 0x4 as libc::c_int as u_int32_t;
        a.perm = st.st_mode | 0o700 as libc::c_int as libc::c_uint;
        if do_mkdir(conn, target, &mut a, 1 as libc::c_int) != 0 as libc::c_int {
            cleanup_exit(255 as libc::c_int);
        }
        target_is_dir = 1 as libc::c_int;
    }
    if target_is_dir != 0 {
        abs_dst = path_append(target, filename);
    } else {
        abs_dst = target;
        target = 0 as *mut libc::c_char;
    }
    crate::log::sshlog(
        b"scp.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"source_sftp\0")).as_ptr(),
        1366 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"copying local %s to remote %s\0" as *const u8 as *const libc::c_char,
        src,
        abs_dst,
    );
    if src_is_dir != 0 && iamrecursive != 0 {
        if upload_dir(
            conn,
            src,
            abs_dst,
            pflag,
            2 as libc::c_int,
            0 as libc::c_int,
            0 as libc::c_int,
            1 as libc::c_int,
            1 as libc::c_int,
        ) != 0 as libc::c_int
        {
            crate::log::sshlog(
                b"scp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"source_sftp\0"))
                    .as_ptr(),
                1371 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"failed to upload directory %s to %s\0" as *const u8 as *const libc::c_char,
                src,
                targ,
            );
            errs = 1 as libc::c_int;
        }
    } else if do_upload(
        conn,
        src,
        abs_dst,
        pflag,
        0 as libc::c_int,
        0 as libc::c_int,
        1 as libc::c_int,
    ) != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"scp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"source_sftp\0")).as_ptr(),
            1375 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"failed to upload file %s to %s\0" as *const u8 as *const libc::c_char,
            src,
            targ,
        );
        errs = 1 as libc::c_int;
    }
    libc::free(abs_dst as *mut libc::c_void);
    libc::free(target as *mut libc::c_void);
}
pub unsafe extern "C" fn source(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char) {
    let mut current_block: u64;
    let mut stb: libc::stat = unsafe { std::mem::zeroed() };
    static mut buffer: BUF = BUF {
        cnt: 0,
        buf: 0 as *const libc::c_char as *mut libc::c_char,
    };
    let mut bp: *mut BUF = 0 as *mut BUF;
    let mut i: off_t = 0;
    let mut statbytes: off_t = 0;
    let mut amt: size_t = 0;
    let mut nr: size_t = 0;
    let mut fd: libc::c_int = -(1 as libc::c_int);
    let mut haderr: libc::c_int = 0;
    let mut indx: libc::c_int = 0;
    let mut last: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut buf: [libc::c_char; 4224] = [0; 4224];
    let mut encname: [libc::c_char; 4096] = [0; 4096];
    let mut len: libc::c_int = 0;
    indx = 0 as libc::c_int;
    while indx < argc {
        name = *argv.offset(indx as isize);
        statbytes = 0 as libc::c_int as off_t;
        len = strlen(name) as libc::c_int;
        while len > 1 as libc::c_int
            && *name.offset((len - 1 as libc::c_int) as isize) as libc::c_int == '/' as i32
        {
            len -= 1;
            *name.offset(len as isize) = '\0' as i32 as libc::c_char;
        }
        fd = libc::open(name, 0 as libc::c_int | 0o4000 as libc::c_int);
        if fd == -(1 as libc::c_int) {
            current_block = 13417990991670220822;
        } else {
            if !(strchr(name, '\n' as i32)).is_null() {
                strnvis(
                    encname.as_mut_ptr(),
                    name,
                    ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
                    0x10 as libc::c_int,
                );
                name = encname.as_mut_ptr();
            }
            if libc::fstat(fd, &mut stb) == -(1 as libc::c_int) {
                current_block = 13417990991670220822;
            } else if stb.st_size < 0 as libc::c_int as libc::c_long {
                run_err(
                    b"%s: %s\0" as *const u8 as *const libc::c_char,
                    name,
                    b"Negative file size\0" as *const u8 as *const libc::c_char,
                );
                current_block = 1443331007555087595;
            } else {
                crate::misc::unset_nonblock(fd);
                match stb.st_mode & 0o170000 as libc::c_int as libc::c_uint {
                    32768 => {
                        last = strrchr(name, '/' as i32);
                        if last.is_null() {
                            last = name;
                        } else {
                            last = last.offset(1);
                            last;
                        }
                        curfile = last;
                        if pflag != 0 {
                            if do_times(remout, verbose_mode, &mut stb) < 0 as libc::c_int {
                                current_block = 1443331007555087595;
                            } else {
                                current_block = 14648156034262866959;
                            }
                        } else {
                            current_block = 14648156034262866959;
                        }
                        match current_block {
                            1443331007555087595 => {}
                            _ => {
                                libc::snprintf(
                                    buf.as_mut_ptr(),
                                    ::core::mem::size_of::<[libc::c_char; 4224]>() as usize,
                                    b"C%04o %lld %s\n\0" as *const u8 as *const libc::c_char,
                                    stb.st_mode
                                        & (0o4000 as libc::c_int
                                            | 0o2000 as libc::c_int
                                            | (0o400 as libc::c_int
                                                | 0o200 as libc::c_int
                                                | 0o100 as libc::c_int)
                                            | (0o400 as libc::c_int
                                                | 0o200 as libc::c_int
                                                | 0o100 as libc::c_int)
                                                >> 3 as libc::c_int
                                            | (0o400 as libc::c_int
                                                | 0o200 as libc::c_int
                                                | 0o100 as libc::c_int)
                                                >> 3 as libc::c_int
                                                >> 3 as libc::c_int)
                                            as libc::c_uint,
                                    stb.st_size as libc::c_longlong,
                                    last,
                                );
                                if verbose_mode != 0 {
                                    fmprintf(
                                        stderr,
                                        b"Sending file modes: %s\0" as *const u8
                                            as *const libc::c_char,
                                        buf.as_mut_ptr(),
                                    );
                                }
                                atomicio(
                                    ::core::mem::transmute::<
                                        Option<
                                            unsafe extern "C" fn(
                                                libc::c_int,
                                                *const libc::c_void,
                                                size_t,
                                            )
                                                -> ssize_t,
                                        >,
                                        Option<
                                            unsafe extern "C" fn(
                                                libc::c_int,
                                                *mut libc::c_void,
                                                size_t,
                                            )
                                                -> ssize_t,
                                        >,
                                    >(Some(
                                        write
                                            as unsafe extern "C" fn(
                                                libc::c_int,
                                                *const libc::c_void,
                                                size_t,
                                            )
                                                -> ssize_t,
                                    )),
                                    remout,
                                    buf.as_mut_ptr() as *mut libc::c_void,
                                    strlen(buf.as_mut_ptr()),
                                );
                                if response() < 0 as libc::c_int {
                                    current_block = 1443331007555087595;
                                } else {
                                    bp = allocbuf(&mut buffer, fd, 16384 as libc::c_int);
                                    if bp.is_null() {
                                        current_block = 1443331007555087595;
                                    } else {
                                        if showprogress != 0 {
                                            start_progress_meter(
                                                curfile,
                                                stb.st_size,
                                                &mut statbytes,
                                            );
                                        }
                                        crate::misc::set_nonblock(remout);
                                        i = 0 as libc::c_int as off_t;
                                        haderr = i as libc::c_int;
                                        while i < stb.st_size {
                                            amt = (*bp).cnt;
                                            if i + amt as off_t > stb.st_size {
                                                amt = (stb.st_size - i) as size_t;
                                            }
                                            if haderr == 0 {
                                                nr = atomicio(
                                                    Some(
                                                        read as unsafe extern "C" fn(
                                                            libc::c_int,
                                                            *mut libc::c_void,
                                                            size_t,
                                                        )
                                                            -> ssize_t,
                                                    ),
                                                    fd,
                                                    (*bp).buf as *mut libc::c_void,
                                                    amt,
                                                );
                                                if nr != amt {
                                                    haderr = *libc::__errno_location();
                                                    memset(
                                                        ((*bp).buf).offset(nr as isize)
                                                            as *mut libc::c_void,
                                                        0 as libc::c_int,
                                                        amt.wrapping_sub(nr),
                                                    );
                                                }
                                            }
                                            if haderr != 0 {
                                                atomicio(
                                                    ::core::mem::transmute::<
                                                        Option<
                                                            unsafe extern "C" fn(
                                                                libc::c_int,
                                                                *const libc::c_void,
                                                                size_t,
                                                            )
                                                                -> ssize_t,
                                                        >,
                                                        Option<
                                                            unsafe extern "C" fn(
                                                                libc::c_int,
                                                                *mut libc::c_void,
                                                                size_t,
                                                            )
                                                                -> ssize_t,
                                                        >,
                                                    >(
                                                        Some(
                                                            write
                                                                as unsafe extern "C" fn(
                                                                    libc::c_int,
                                                                    *const libc::c_void,
                                                                    size_t,
                                                                )
                                                                    -> ssize_t,
                                                        ),
                                                    ),
                                                    remout,
                                                    (*bp).buf as *mut libc::c_void,
                                                    amt,
                                                );
                                                memset(
                                                    (*bp).buf as *mut libc::c_void,
                                                    0 as libc::c_int,
                                                    amt,
                                                );
                                            } else if atomicio6(
                                                ::core::mem::transmute::<
                                                    Option<
                                                        unsafe extern "C" fn(
                                                            libc::c_int,
                                                            *const libc::c_void,
                                                            size_t,
                                                        )
                                                            -> ssize_t,
                                                    >,
                                                    Option<
                                                        unsafe extern "C" fn(
                                                            libc::c_int,
                                                            *mut libc::c_void,
                                                            size_t,
                                                        )
                                                            -> ssize_t,
                                                    >,
                                                >(
                                                    Some(
                                                        write
                                                            as unsafe extern "C" fn(
                                                                libc::c_int,
                                                                *const libc::c_void,
                                                                size_t,
                                                            )
                                                                -> ssize_t,
                                                    ),
                                                ),
                                                remout,
                                                (*bp).buf as *mut libc::c_void,
                                                amt,
                                                Some(
                                                    scpio
                                                        as unsafe extern "C" fn(
                                                            *mut libc::c_void,
                                                            size_t,
                                                        )
                                                            -> libc::c_int,
                                                ),
                                                &mut statbytes as *mut off_t as *mut libc::c_void,
                                            ) != amt
                                            {
                                                haderr = *libc::__errno_location();
                                            }
                                            i = (i as libc::c_ulong).wrapping_add((*bp).cnt)
                                                as off_t
                                                as off_t;
                                        }
                                        crate::misc::unset_nonblock(remout);
                                        if fd != -(1 as libc::c_int) {
                                            if close(fd) == -(1 as libc::c_int) && haderr == 0 {
                                                haderr = *libc::__errno_location();
                                            }
                                            fd = -(1 as libc::c_int);
                                        }
                                        if haderr == 0 {
                                            atomicio(
                                                ::core::mem::transmute::<
                                                    Option<
                                                        unsafe extern "C" fn(
                                                            libc::c_int,
                                                            *const libc::c_void,
                                                            size_t,
                                                        )
                                                            -> ssize_t,
                                                    >,
                                                    Option<
                                                        unsafe extern "C" fn(
                                                            libc::c_int,
                                                            *mut libc::c_void,
                                                            size_t,
                                                        )
                                                            -> ssize_t,
                                                    >,
                                                >(
                                                    Some(
                                                        write
                                                            as unsafe extern "C" fn(
                                                                libc::c_int,
                                                                *const libc::c_void,
                                                                size_t,
                                                            )
                                                                -> ssize_t,
                                                    ),
                                                ),
                                                remout,
                                                b"\0" as *const u8 as *const libc::c_char
                                                    as *mut libc::c_void,
                                                1 as libc::c_int as size_t,
                                            );
                                        } else {
                                            run_err(
                                                b"%s: %s\0" as *const u8 as *const libc::c_char,
                                                name,
                                                strerror(haderr),
                                            );
                                        }
                                        response();
                                        if showprogress != 0 {
                                            stop_progress_meter();
                                        }
                                        current_block = 4644295000439058019;
                                    }
                                }
                            }
                        }
                    }
                    16384 => {
                        if iamrecursive != 0 {
                            rsource(name, &mut stb);
                            current_block = 1443331007555087595;
                        } else {
                            current_block = 9885440278726056835;
                        }
                    }
                    _ => {
                        current_block = 9885440278726056835;
                    }
                }
                match current_block {
                    1443331007555087595 => {}
                    4644295000439058019 => {}
                    _ => {
                        run_err(
                            b"%s: not a regular file\0" as *const u8 as *const libc::c_char,
                            name,
                        );
                        current_block = 1443331007555087595;
                    }
                }
            }
        }
        match current_block {
            13417990991670220822 => {
                run_err(
                    b"%s: %s\0" as *const u8 as *const libc::c_char,
                    name,
                    strerror(*libc::__errno_location()),
                );
                current_block = 1443331007555087595;
            }
            _ => {}
        }
        match current_block {
            1443331007555087595 => {
                if fd != -(1 as libc::c_int) {
                    close(fd);
                    fd = -(1 as libc::c_int);
                }
            }
            _ => {}
        }
        indx += 1;
        indx;
    }
}
pub unsafe extern "C" fn rsource(mut name: *mut libc::c_char, mut statp: *mut libc::stat) {
    let mut dirp: *mut DIR = 0 as *mut DIR;
    let mut dp: *mut dirent = 0 as *mut dirent;
    let mut last: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut vect: [*mut libc::c_char; 1] = [0 as *mut libc::c_char; 1];
    let mut path: [libc::c_char; 4096] = [0; 4096];
    dirp = opendir(name);
    if dirp.is_null() {
        run_err(
            b"%s: %s\0" as *const u8 as *const libc::c_char,
            name,
            strerror(*libc::__errno_location()),
        );
        return;
    }
    last = strrchr(name, '/' as i32);
    if last.is_null() {
        last = name;
    } else {
        last = last.offset(1);
        last;
    }
    if pflag != 0 {
        if do_times(remout, verbose_mode, statp) < 0 as libc::c_int {
            closedir(dirp);
            return;
        }
    }
    libc::snprintf(
        path.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 4096]>() as usize,
        b"D%04o %d %.1024s\n\0" as *const u8 as *const libc::c_char,
        (*statp).st_mode
            & (0o4000 as libc::c_int
                | 0o2000 as libc::c_int
                | (0o400 as libc::c_int | 0o200 as libc::c_int | 0o100 as libc::c_int)
                | (0o400 as libc::c_int | 0o200 as libc::c_int | 0o100 as libc::c_int)
                    >> 3 as libc::c_int
                | (0o400 as libc::c_int | 0o200 as libc::c_int | 0o100 as libc::c_int)
                    >> 3 as libc::c_int
                    >> 3 as libc::c_int) as libc::c_uint,
        0 as libc::c_int,
        last,
    );
    if verbose_mode != 0 {
        fmprintf(
            stderr,
            b"Entering directory: %s\0" as *const u8 as *const libc::c_char,
            path.as_mut_ptr(),
        );
    }
    atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        remout,
        path.as_mut_ptr() as *mut libc::c_void,
        strlen(path.as_mut_ptr()),
    );
    if response() < 0 as libc::c_int {
        closedir(dirp);
        return;
    }
    loop {
        dp = readdir(dirp);
        if dp.is_null() {
            break;
        }
        if (*dp).d_ino == 0 as libc::c_int as libc::c_ulong {
            continue;
        }
        if strcmp(
            ((*dp).d_name).as_mut_ptr(),
            b".\0" as *const u8 as *const libc::c_char,
        ) == 0
            || strcmp(
                ((*dp).d_name).as_mut_ptr(),
                b"..\0" as *const u8 as *const libc::c_char,
            ) == 0
        {
            continue;
        }
        if (strlen(name))
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_add(strlen(((*dp).d_name).as_mut_ptr()))
            >= (::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        {
            run_err(
                b"%s/%s: name too long\0" as *const u8 as *const libc::c_char,
                name,
                ((*dp).d_name).as_mut_ptr(),
            );
        } else {
            libc::snprintf(
                path.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 4096]>() as usize,
                b"%s/%s\0" as *const u8 as *const libc::c_char,
                name,
                ((*dp).d_name).as_mut_ptr(),
            );
            vect[0 as libc::c_int as usize] = path.as_mut_ptr();
            source(1 as libc::c_int, vect.as_mut_ptr());
        }
    }
    closedir(dirp);
    atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        remout,
        b"E\n\0" as *const u8 as *const libc::c_char as *mut libc::c_void,
        2 as libc::c_int as size_t,
    );
    response();
}
pub unsafe extern "C" fn sink_sftp(
    mut _argc: libc::c_int,
    mut dst: *mut libc::c_char,
    mut src: *const libc::c_char,
    mut conn: *mut sftp_conn,
) {
    let mut current_block: u64;
    let mut abs_src: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut abs_dst: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut g: _ssh_compat_glob_t = _ssh_compat_glob_t {
        gl_pathc: 0,
        gl_matchc: 0,
        gl_offs: 0,
        gl_flags: 0,
        gl_pathv: 0 as *mut *mut libc::c_char,
        gl_statv: 0 as *mut *mut libc::stat,
        gl_errfunc: None,
        gl_closedir: None,
        gl_readdir: None,
        gl_opendir: None,
        gl_lstat: None,
        gl_stat: None,
    };
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut err: libc::c_int = 0 as libc::c_int;
    let mut dst_is_dir: libc::c_int = 0;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    memset(
        &mut g as *mut _ssh_compat_glob_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<_ssh_compat_glob_t>() as libc::c_ulong,
    );
    abs_src = prepare_remote_path(conn, src);
    if abs_src.is_null() {
        err = -(1 as libc::c_int);
    } else {
        crate::log::sshlog(
            b"scp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"sink_sftp\0")).as_ptr(),
            1565 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"copying remote %s to local %s\0" as *const u8 as *const libc::c_char,
            abs_src,
            dst,
        );
        r = remote_glob(
            conn,
            abs_src,
            0x10 as libc::c_int | 0x8 as libc::c_int,
            None,
            &mut g,
        );
        if r != 0 as libc::c_int {
            if r == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"scp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"sink_sftp\0"))
                        .as_ptr(),
                    1569 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s: too many glob matches\0" as *const u8 as *const libc::c_char,
                    src,
                );
            } else {
                crate::log::sshlog(
                    b"scp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"sink_sftp\0"))
                        .as_ptr(),
                    1571 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s: %s\0" as *const u8 as *const libc::c_char,
                    src,
                    strerror(2 as libc::c_int),
                );
            }
            err = -(1 as libc::c_int);
        } else {
            if g.gl_matchc == 0 as libc::c_int as libc::c_ulong
                && g.gl_pathc == 1 as libc::c_int as libc::c_ulong
                && !(*(g.gl_pathv).offset(0 as libc::c_int as isize)).is_null()
            {
                if (do_stat(
                    conn,
                    *(g.gl_pathv).offset(0 as libc::c_int as isize),
                    1 as libc::c_int,
                ))
                .is_null()
                {
                    crate::log::sshlog(
                        b"scp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"sink_sftp\0"))
                            .as_ptr(),
                        1584 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s: %s\0" as *const u8 as *const libc::c_char,
                        src,
                        strerror(2 as libc::c_int),
                    );
                    err = -(1 as libc::c_int);
                    current_block = 10329178916078510120;
                } else {
                    current_block = 4166486009154926805;
                }
            } else {
                current_block = 4166486009154926805;
            }
            match current_block {
                10329178916078510120 => {}
                _ => {
                    r = libc::stat(dst, &mut st);
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"scp.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(
                                b"sink_sftp\0",
                            ))
                            .as_ptr(),
                            1591 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"libc::stat local \"%s\": %s\0" as *const u8 as *const libc::c_char,
                            dst,
                            strerror(*libc::__errno_location()),
                        );
                    }
                    dst_is_dir = (r == 0 as libc::c_int
                        && st.st_mode & 0o170000 as libc::c_int as libc::c_uint
                            == 0o40000 as libc::c_int as libc::c_uint)
                        as libc::c_int;
                    if g.gl_matchc > 1 as libc::c_int as libc::c_ulong && dst_is_dir == 0 {
                        if r == 0 as libc::c_int {
                            crate::log::sshlog(
                                b"scp.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<
                                    &[u8; 10],
                                    &[libc::c_char; 10],
                                >(b"sink_sftp\0"))
                                    .as_ptr(),
                                1597 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"Multiple files match pattern, but destination \"%s\" is not a directory\0"
                                    as *const u8 as *const libc::c_char,
                                dst,
                            );
                            err = -(1 as libc::c_int);
                            current_block = 10329178916078510120;
                        } else {
                            crate::log::sshlog(
                                b"scp.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(
                                    b"sink_sftp\0",
                                ))
                                .as_ptr(),
                                1601 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"creating destination \"%s\"\0" as *const u8
                                    as *const libc::c_char,
                                dst,
                            );
                            if libc::mkdir(dst, 0o777 as libc::c_int as __mode_t)
                                != 0 as libc::c_int
                            {
                                crate::log::sshlog(
                                    b"scp.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(
                                        b"sink_sftp\0",
                                    ))
                                    .as_ptr(),
                                    1603 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"local mkdir \"%s\": %s\0" as *const u8 as *const libc::c_char,
                                    dst,
                                    strerror(*libc::__errno_location()),
                                );
                                err = -(1 as libc::c_int);
                                current_block = 10329178916078510120;
                            } else {
                                dst_is_dir = 1 as libc::c_int;
                                current_block = 11194104282611034094;
                            }
                        }
                    } else {
                        current_block = 11194104282611034094;
                    }
                    match current_block {
                        10329178916078510120 => {}
                        _ => {
                            i = 0 as libc::c_int;
                            while !(*(g.gl_pathv).offset(i as isize)).is_null() && interrupted == 0
                            {
                                tmp = xstrdup(*(g.gl_pathv).offset(i as isize));
                                filename = __xpg_basename(tmp);
                                if filename.is_null() {
                                    crate::log::sshlog(
                                        b"scp.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(
                                            b"sink_sftp\0",
                                        ))
                                        .as_ptr(),
                                        1613 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"basename %s: %s\0" as *const u8 as *const libc::c_char,
                                        tmp,
                                        strerror(*libc::__errno_location()),
                                    );
                                    err = -(1 as libc::c_int);
                                    break;
                                } else {
                                    if dst_is_dir != 0 {
                                        abs_dst = path_append(dst, filename);
                                    } else {
                                        abs_dst = xstrdup(dst);
                                    }
                                    crate::log::sshlog(
                                        b"scp.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(
                                            b"sink_sftp\0",
                                        ))
                                        .as_ptr(),
                                        1623 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG1,
                                        0 as *const libc::c_char,
                                        b"Fetching %s to %s\n\0" as *const u8
                                            as *const libc::c_char,
                                        *(g.gl_pathv).offset(i as isize),
                                        abs_dst,
                                    );
                                    if globpath_is_dir(*(g.gl_pathv).offset(i as isize)) != 0
                                        && iamrecursive != 0
                                    {
                                        if download_dir(
                                            conn,
                                            *(g.gl_pathv).offset(i as isize),
                                            abs_dst,
                                            0 as *mut Attrib,
                                            pflag,
                                            2 as libc::c_int,
                                            0 as libc::c_int,
                                            0 as libc::c_int,
                                            1 as libc::c_int,
                                            1 as libc::c_int,
                                        ) == -(1 as libc::c_int)
                                        {
                                            err = -(1 as libc::c_int);
                                        }
                                    } else if crate::sftp_client::do_download(
                                        conn,
                                        *(g.gl_pathv).offset(i as isize),
                                        abs_dst,
                                        0 as *mut Attrib,
                                        pflag,
                                        0 as libc::c_int,
                                        0 as libc::c_int,
                                        1 as libc::c_int,
                                    ) == -(1 as libc::c_int)
                                    {
                                        err = -(1 as libc::c_int);
                                    }
                                    libc::free(abs_dst as *mut libc::c_void);
                                    abs_dst = 0 as *mut libc::c_char;
                                    libc::free(tmp as *mut libc::c_void);
                                    tmp = 0 as *mut libc::c_char;
                                    i += 1;
                                    i;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    libc::free(abs_src as *mut libc::c_void);
    libc::free(tmp as *mut libc::c_void);
    _ssh__compat_globfree(&mut g);
    if err == -(1 as libc::c_int) {
        errs = 1 as libc::c_int;
    }
}
pub unsafe extern "C" fn sink(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
    mut src: *const libc::c_char,
) {
    let mut current_block: u64;
    static mut buffer: BUF = BUF {
        cnt: 0,
        buf: 0 as *const libc::c_char as *mut libc::c_char,
    };
    let mut stb: libc::stat = unsafe { std::mem::zeroed() };
    let mut bp: *mut BUF = 0 as *mut BUF;
    let mut i: off_t = 0;
    let mut j: size_t = 0;
    let mut count: size_t = 0;
    let mut amt: libc::c_int = 0;
    let mut exists: libc::c_int = 0;
    let mut first: libc::c_int = 0;
    let mut ofd: libc::c_int = 0;
    let mut mode: mode_t = 0;
    let mut omode: mode_t = 0;
    let mut mask: mode_t = 0;
    let mut size: off_t = 0;
    let mut statbytes: off_t = 0;
    let mut ull: libc::c_ulonglong = 0;
    let mut setimes: libc::c_int = 0;
    let mut targisdir: libc::c_int = 0;
    let mut wrerr: libc::c_int = 0;
    let mut ch: libc::c_char = 0;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut np: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut targ: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut why: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut vect: [*mut libc::c_char; 1] = [0 as *mut libc::c_char; 1];
    let mut buf: [libc::c_char; 2048] = [0; 2048];
    let mut visbuf: [libc::c_char; 2048] = [0; 2048];
    let mut patterns: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut n: size_t = 0;
    let mut npatterns: size_t = 0 as libc::c_int as size_t;
    let mut tv: [libc::timeval; 2] = [libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    }; 2];
    if ::core::mem::size_of::<time_t>() as libc::c_ulong == 4 as libc::c_int as libc::c_ulong
        && 0 as libc::c_int > 2147483647 as libc::c_int
        || ::core::mem::size_of::<time_t>() as libc::c_ulong == 8 as libc::c_int as libc::c_ulong
            && 0 as libc::c_int as libc::c_long > 9223372036854775807 as libc::c_long
        || ::core::mem::size_of::<time_t>() as libc::c_ulong != 4 as libc::c_int as libc::c_ulong
            && ::core::mem::size_of::<time_t>() as libc::c_ulong
                != 8 as libc::c_int as libc::c_ulong
        || (::core::mem::size_of::<off_t>() as libc::c_ulong == 4 as libc::c_int as libc::c_ulong
            && 0 as libc::c_int > 2147483647 as libc::c_int
            || ::core::mem::size_of::<off_t>() as libc::c_ulong
                == 8 as libc::c_int as libc::c_ulong
                && 0 as libc::c_int as libc::c_long > 9223372036854775807 as libc::c_long
            || ::core::mem::size_of::<off_t>() as libc::c_ulong
                != 4 as libc::c_int as libc::c_ulong
                && ::core::mem::size_of::<off_t>() as libc::c_ulong
                    != 8 as libc::c_int as libc::c_ulong)
    {
        why = b"Unexpected off_t/time_t size\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char;
    } else {
        targisdir = 0 as libc::c_int;
        setimes = targisdir;
        mask = libc::umask(0 as libc::c_int as __mode_t);
        if pflag == 0 {
            libc::umask(mask);
        }
        if argc != 1 as libc::c_int {
            run_err(b"ambiguous target\0" as *const u8 as *const libc::c_char);
            libc::exit(1 as libc::c_int);
        }
        targ = *argv;
        if targetshouldbedirectory != 0 {
            verifydir(targ);
        }
        atomicio(
            ::core::mem::transmute::<
                Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
                Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
            >(Some(
                write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
            )),
            remout,
            b"\0" as *const u8 as *const libc::c_char as *mut libc::c_void,
            1 as libc::c_int as size_t,
        );
        if libc::stat(targ, &mut stb) == 0 as libc::c_int
            && stb.st_mode & 0o170000 as libc::c_int as libc::c_uint
                == 0o40000 as libc::c_int as libc::c_uint
        {
            targisdir = 1 as libc::c_int;
        }
        if !src.is_null() && iamrecursive == 0 && Tflag == 0 {
            if brace_expand(src, &mut patterns, &mut npatterns) != 0 as libc::c_int {
                sshfatal(
                    b"scp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"sink\0")).as_ptr(),
                    1699 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"could not expand pattern\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        first = 1 as libc::c_int;
        's_115: loop {
            cp = buf.as_mut_ptr();
            if atomicio(
                Some(
                    read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t,
                ),
                remin,
                cp as *mut libc::c_void,
                1 as libc::c_int as size_t,
            ) != 1 as libc::c_int as libc::c_ulong
            {
                current_block = 12610533779684660077;
                break;
            }
            let fresh3 = cp;
            cp = cp.offset(1);
            if *fresh3 as libc::c_int == '\n' as i32 {
                why = b"unexpected <newline>\0" as *const u8 as *const libc::c_char
                    as *mut libc::c_char;
                current_block = 2582807901502089632;
                break;
            } else {
                loop {
                    if atomicio(
                        Some(
                            read as unsafe extern "C" fn(
                                libc::c_int,
                                *mut libc::c_void,
                                size_t,
                            ) -> ssize_t,
                        ),
                        remin,
                        &mut ch as *mut libc::c_char as *mut libc::c_void,
                        ::core::mem::size_of::<libc::c_char>() as libc::c_ulong,
                    ) != ::core::mem::size_of::<libc::c_char>() as libc::c_ulong
                    {
                        why = b"lost connection\0" as *const u8 as *const libc::c_char
                            as *mut libc::c_char;
                        current_block = 2582807901502089632;
                        break 's_115;
                    } else {
                        let fresh4 = cp;
                        cp = cp.offset(1);
                        *fresh4 = ch;
                        if !(cp
                            < &mut *buf.as_mut_ptr().offset(
                                (::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                                    as isize,
                            ) as *mut libc::c_char
                            && ch as libc::c_int != '\n' as i32)
                        {
                            break;
                        }
                    }
                }
                *cp = 0 as libc::c_int as libc::c_char;
                if verbose_mode != 0 {
                    fmprintf(
                        stderr,
                        b"Sink: %s\0" as *const u8 as *const libc::c_char,
                        buf.as_mut_ptr(),
                    );
                }
                if buf[0 as libc::c_int as usize] as libc::c_int == '\u{1}' as i32
                    || buf[0 as libc::c_int as usize] as libc::c_int == '\u{2}' as i32
                {
                    if iamremote == 0 as libc::c_int {
                        snmprintf(
                            visbuf.as_mut_ptr(),
                            ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong,
                            0 as *mut libc::c_int,
                            b"%s\0" as *const u8 as *const libc::c_char,
                            buf.as_mut_ptr().offset(1 as libc::c_int as isize),
                        );
                        atomicio(
                            ::core::mem::transmute::<
                                Option<
                                    unsafe extern "C" fn(
                                        libc::c_int,
                                        *const libc::c_void,
                                        size_t,
                                    )
                                        -> ssize_t,
                                >,
                                Option<
                                    unsafe extern "C" fn(
                                        libc::c_int,
                                        *mut libc::c_void,
                                        size_t,
                                    )
                                        -> ssize_t,
                                >,
                            >(Some(
                                write
                                    as unsafe extern "C" fn(
                                        libc::c_int,
                                        *const libc::c_void,
                                        size_t,
                                    )
                                        -> ssize_t,
                            )),
                            2 as libc::c_int,
                            visbuf.as_mut_ptr() as *mut libc::c_void,
                            strlen(visbuf.as_mut_ptr()),
                        );
                    }
                    if buf[0 as libc::c_int as usize] as libc::c_int == '\u{2}' as i32 {
                        libc::exit(1 as libc::c_int);
                    }
                    errs += 1;
                    errs;
                } else if buf[0 as libc::c_int as usize] as libc::c_int == 'E' as i32 {
                    atomicio(
                        ::core::mem::transmute::<
                            Option<
                                unsafe extern "C" fn(
                                    libc::c_int,
                                    *const libc::c_void,
                                    size_t,
                                ) -> ssize_t,
                            >,
                            Option<
                                unsafe extern "C" fn(
                                    libc::c_int,
                                    *mut libc::c_void,
                                    size_t,
                                ) -> ssize_t,
                            >,
                        >(Some(
                            write
                                as unsafe extern "C" fn(
                                    libc::c_int,
                                    *const libc::c_void,
                                    size_t,
                                ) -> ssize_t,
                        )),
                        remout,
                        b"\0" as *const u8 as *const libc::c_char as *mut libc::c_void,
                        1 as libc::c_int as size_t,
                    );
                    current_block = 12610533779684660077;
                    break;
                } else {
                    if ch as libc::c_int == '\n' as i32 {
                        cp = cp.offset(-1);
                        *cp = 0 as libc::c_int as libc::c_char;
                    }
                    cp = buf.as_mut_ptr();
                    if *cp as libc::c_int == 'T' as i32 {
                        setimes += 1;
                        setimes;
                        cp = cp.offset(1);
                        cp;
                        if *(*__ctype_b_loc()).offset(*cp as libc::c_uchar as libc::c_int as isize)
                            as libc::c_int
                            & _ISdigit as libc::c_int as libc::c_ushort as libc::c_int
                            == 0
                        {
                            why = b"mtime.sec not present\0" as *const u8 as *const libc::c_char
                                as *mut libc::c_char;
                            current_block = 2582807901502089632;
                            break;
                        } else {
                            ull = libc::strtoull(cp, &mut cp, 10 as libc::c_int);
                            if cp.is_null() || {
                                let fresh5 = cp;
                                cp = cp.offset(1);
                                *fresh5 as libc::c_int != ' ' as i32
                            } {
                                why = b"mtime.sec not delimited\0" as *const u8
                                    as *const libc::c_char
                                    as *mut libc::c_char;
                                current_block = 2582807901502089632;
                                break;
                            } else {
                                if ::core::mem::size_of::<time_t>() as libc::c_ulong
                                    == 4 as libc::c_int as libc::c_ulong
                                    && ull > 2147483647 as libc::c_int as libc::c_ulonglong
                                    || ::core::mem::size_of::<time_t>() as libc::c_ulong
                                        == 8 as libc::c_int as libc::c_ulong
                                        && ull
                                            > 9223372036854775807 as libc::c_long
                                                as libc::c_ulonglong
                                    || ::core::mem::size_of::<time_t>() as libc::c_ulong
                                        != 4 as libc::c_int as libc::c_ulong
                                        && ::core::mem::size_of::<time_t>() as libc::c_ulong
                                            != 8 as libc::c_int as libc::c_ulong
                                {
                                    setimes = 0 as libc::c_int;
                                }
                                tv[1 as libc::c_int as usize].tv_sec = ull as __time_t;
                                tv[1 as libc::c_int as usize].tv_usec =
                                    strtol(cp, &mut cp, 10 as libc::c_int);
                                if cp.is_null()
                                    || {
                                        let fresh6 = cp;
                                        cp = cp.offset(1);
                                        *fresh6 as libc::c_int != ' ' as i32
                                    }
                                    || tv[1 as libc::c_int as usize].tv_usec
                                        < 0 as libc::c_int as libc::c_long
                                    || tv[1 as libc::c_int as usize].tv_usec
                                        > 999999 as libc::c_int as libc::c_long
                                {
                                    why = b"mtime.usec not delimited\0" as *const u8
                                        as *const libc::c_char
                                        as *mut libc::c_char;
                                    current_block = 2582807901502089632;
                                    break;
                                } else if *(*__ctype_b_loc())
                                    .offset(*cp as libc::c_uchar as libc::c_int as isize)
                                    as libc::c_int
                                    & _ISdigit as libc::c_int as libc::c_ushort as libc::c_int
                                    == 0
                                {
                                    why = b"atime.sec not present\0" as *const u8
                                        as *const libc::c_char
                                        as *mut libc::c_char;
                                    current_block = 2582807901502089632;
                                    break;
                                } else {
                                    ull = libc::strtoull(cp, &mut cp, 10 as libc::c_int);
                                    if cp.is_null() || {
                                        let fresh7 = cp;
                                        cp = cp.offset(1);
                                        *fresh7 as libc::c_int != ' ' as i32
                                    } {
                                        why = b"atime.sec not delimited\0" as *const u8
                                            as *const libc::c_char
                                            as *mut libc::c_char;
                                        current_block = 2582807901502089632;
                                        break;
                                    } else {
                                        if ::core::mem::size_of::<time_t>() as libc::c_ulong
                                            == 4 as libc::c_int as libc::c_ulong
                                            && ull > 2147483647 as libc::c_int as libc::c_ulonglong
                                            || ::core::mem::size_of::<time_t>() as libc::c_ulong
                                                == 8 as libc::c_int as libc::c_ulong
                                                && ull
                                                    > 9223372036854775807 as libc::c_long
                                                        as libc::c_ulonglong
                                            || ::core::mem::size_of::<time_t>() as libc::c_ulong
                                                != 4 as libc::c_int as libc::c_ulong
                                                && ::core::mem::size_of::<time_t>() as libc::c_ulong
                                                    != 8 as libc::c_int as libc::c_ulong
                                        {
                                            setimes = 0 as libc::c_int;
                                        }
                                        tv[0 as libc::c_int as usize].tv_sec = ull as __time_t;
                                        tv[0 as libc::c_int as usize].tv_usec =
                                            strtol(cp, &mut cp, 10 as libc::c_int);
                                        if cp.is_null()
                                            || {
                                                let fresh8 = cp;
                                                cp = cp.offset(1);
                                                *fresh8 as libc::c_int != '\0' as i32
                                            }
                                            || tv[0 as libc::c_int as usize].tv_usec
                                                < 0 as libc::c_int as libc::c_long
                                            || tv[0 as libc::c_int as usize].tv_usec
                                                > 999999 as libc::c_int as libc::c_long
                                        {
                                            why = b"atime.usec not delimited\0" as *const u8
                                                as *const libc::c_char
                                                as *mut libc::c_char;
                                            current_block = 2582807901502089632;
                                            break;
                                        } else {
                                            atomicio(
                                                ::core::mem::transmute::<
                                                    Option<
                                                        unsafe extern "C" fn(
                                                            libc::c_int,
                                                            *const libc::c_void,
                                                            size_t,
                                                        )
                                                            -> ssize_t,
                                                    >,
                                                    Option<
                                                        unsafe extern "C" fn(
                                                            libc::c_int,
                                                            *mut libc::c_void,
                                                            size_t,
                                                        )
                                                            -> ssize_t,
                                                    >,
                                                >(
                                                    Some(
                                                        write
                                                            as unsafe extern "C" fn(
                                                                libc::c_int,
                                                                *const libc::c_void,
                                                                size_t,
                                                            )
                                                                -> ssize_t,
                                                    ),
                                                ),
                                                remout,
                                                b"\0" as *const u8 as *const libc::c_char
                                                    as *mut libc::c_void,
                                                1 as libc::c_int as size_t,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    } else if *cp as libc::c_int != 'C' as i32 && *cp as libc::c_int != 'D' as i32 {
                        if first != 0 {
                            run_err(b"%s\0" as *const u8 as *const libc::c_char, cp);
                            libc::exit(1 as libc::c_int);
                        }
                        why = b"expected control record\0" as *const u8 as *const libc::c_char
                            as *mut libc::c_char;
                        current_block = 2582807901502089632;
                        break;
                    } else {
                        mode = 0 as libc::c_int as mode_t;
                        cp = cp.offset(1);
                        cp;
                        while cp < buf.as_mut_ptr().offset(5 as libc::c_int as isize) {
                            if (*cp as libc::c_int) < '0' as i32 || *cp as libc::c_int > '7' as i32
                            {
                                why = b"bad mode\0" as *const u8 as *const libc::c_char
                                    as *mut libc::c_char;
                                current_block = 2582807901502089632;
                                break 's_115;
                            } else {
                                mode = mode << 3 as libc::c_int
                                    | (*cp as libc::c_int - '0' as i32) as libc::c_uint;
                                cp = cp.offset(1);
                                cp;
                            }
                        }
                        if pflag == 0 {
                            mode &= !mask;
                        }
                        let fresh9 = cp;
                        cp = cp.offset(1);
                        if *fresh9 as libc::c_int != ' ' as i32 {
                            why = b"mode not delimited\0" as *const u8 as *const libc::c_char
                                as *mut libc::c_char;
                            current_block = 2582807901502089632;
                            break;
                        } else if *(*__ctype_b_loc())
                            .offset(*cp as libc::c_uchar as libc::c_int as isize)
                            as libc::c_int
                            & _ISdigit as libc::c_int as libc::c_ushort as libc::c_int
                            == 0
                        {
                            why = b"size not present\0" as *const u8 as *const libc::c_char
                                as *mut libc::c_char;
                            current_block = 2582807901502089632;
                            break;
                        } else {
                            ull = libc::strtoull(cp, &mut cp, 10 as libc::c_int);
                            if cp.is_null() || {
                                let fresh10 = cp;
                                cp = cp.offset(1);
                                *fresh10 as libc::c_int != ' ' as i32
                            } {
                                why = b"size not delimited\0" as *const u8 as *const libc::c_char
                                    as *mut libc::c_char;
                                current_block = 2582807901502089632;
                                break;
                            } else if ::core::mem::size_of::<off_t>() as libc::c_ulong
                                == 4 as libc::c_int as libc::c_ulong
                                && ull > 2147483647 as libc::c_int as libc::c_ulonglong
                                || ::core::mem::size_of::<off_t>() as libc::c_ulong
                                    == 8 as libc::c_int as libc::c_ulong
                                    && ull
                                        > 9223372036854775807 as libc::c_long as libc::c_ulonglong
                                || ::core::mem::size_of::<off_t>() as libc::c_ulong
                                    != 4 as libc::c_int as libc::c_ulong
                                    && ::core::mem::size_of::<off_t>() as libc::c_ulong
                                        != 8 as libc::c_int as libc::c_ulong
                            {
                                why = b"size out of range\0" as *const u8 as *const libc::c_char
                                    as *mut libc::c_char;
                                current_block = 2582807901502089632;
                                break;
                            } else {
                                size = ull as off_t;
                                if *cp as libc::c_int == '\0' as i32
                                    || !(strchr(cp, '/' as i32)).is_null()
                                    || strcmp(cp, b".\0" as *const u8 as *const libc::c_char)
                                        == 0 as libc::c_int
                                    || strcmp(cp, b"..\0" as *const u8 as *const libc::c_char)
                                        == 0 as libc::c_int
                                {
                                    run_err(
                                        b"error: unexpected filename: %s\0" as *const u8
                                            as *const libc::c_char,
                                        cp,
                                    );
                                    libc::exit(1 as libc::c_int);
                                }
                                if npatterns > 0 as libc::c_int as libc::c_ulong {
                                    n = 0 as libc::c_int as size_t;
                                    while n < npatterns {
                                        if strcmp(*patterns.offset(n as isize), cp)
                                            == 0 as libc::c_int
                                            || fnmatch(
                                                *patterns.offset(n as isize),
                                                cp,
                                                0 as libc::c_int,
                                            ) == 0 as libc::c_int
                                        {
                                            break;
                                        }
                                        n = n.wrapping_add(1);
                                        n;
                                    }
                                    if n >= npatterns {
                                        why = b"filename does not match request\0" as *const u8
                                            as *const libc::c_char
                                            as *mut libc::c_char;
                                        current_block = 2582807901502089632;
                                        break;
                                    }
                                }
                                if targisdir != 0 {
                                    static mut namebuf: *mut libc::c_char =
                                        0 as *const libc::c_char as *mut libc::c_char;
                                    static mut cursize: size_t = 0;
                                    let mut need: size_t = 0;
                                    need = (strlen(targ))
                                        .wrapping_add(strlen(cp))
                                        .wrapping_add(250 as libc::c_int as libc::c_ulong);
                                    if need > cursize {
                                        libc::free(namebuf as *mut libc::c_void);
                                        namebuf = xmalloc(need) as *mut libc::c_char;
                                        cursize = need;
                                    }
                                    libc::snprintf(
                                        namebuf,
                                        need as usize,
                                        b"%s%s%s\0" as *const u8 as *const libc::c_char,
                                        targ,
                                        if strcmp(targ, b"/\0" as *const u8 as *const libc::c_char)
                                            != 0
                                        {
                                            b"/\0" as *const u8 as *const libc::c_char
                                        } else {
                                            b"\0" as *const u8 as *const libc::c_char
                                        },
                                        cp,
                                    );
                                    np = namebuf;
                                } else {
                                    np = targ;
                                }
                                curfile = cp;
                                exists =
                                    (libc::stat(np, &mut stb) == 0 as libc::c_int) as libc::c_int;
                                if buf[0 as libc::c_int as usize] as libc::c_int == 'D' as i32 {
                                    let mut mod_flag: libc::c_int = pflag;
                                    if iamrecursive == 0 {
                                        why = b"received directory without -r\0" as *const u8
                                            as *const libc::c_char
                                            as *mut libc::c_char;
                                        current_block = 2582807901502089632;
                                        break;
                                    } else {
                                        if exists != 0 {
                                            if !(stb.st_mode
                                                & 0o170000 as libc::c_int as libc::c_uint
                                                == 0o40000 as libc::c_int as libc::c_uint)
                                            {
                                                *libc::__errno_location() = 20 as libc::c_int;
                                                current_block = 11551238854158739040;
                                            } else {
                                                if pflag != 0 {
                                                    libc::chmod(np, mode);
                                                }
                                                current_block = 7079180960716815705;
                                            }
                                        } else {
                                            mod_flag = 1 as libc::c_int;
                                            if libc::mkdir(
                                                np,
                                                mode | (0o400 as libc::c_int
                                                    | 0o200 as libc::c_int
                                                    | 0o100 as libc::c_int)
                                                    as libc::c_uint,
                                            ) == -(1 as libc::c_int)
                                            {
                                                current_block = 11551238854158739040;
                                            } else {
                                                current_block = 7079180960716815705;
                                            }
                                        }
                                        match current_block {
                                            11551238854158739040 => {}
                                            _ => {
                                                vect[0 as libc::c_int as usize] = xstrdup(np);
                                                sink(1 as libc::c_int, vect.as_mut_ptr(), src);
                                                if setimes != 0 {
                                                    setimes = 0 as libc::c_int;
                                                    libc::utimes(
                                                        vect[0 as libc::c_int as usize],
                                                        tv.as_mut_ptr() as *const libc::timeval,
                                                    );
                                                }
                                                if mod_flag != 0 {
                                                    libc::chmod(
                                                        vect[0 as libc::c_int as usize],
                                                        mode,
                                                    );
                                                }
                                                libc::free(
                                                    vect[0 as libc::c_int as usize]
                                                        as *mut libc::c_void,
                                                );
                                                current_block = 5783071609795492627;
                                            }
                                        }
                                    }
                                } else {
                                    omode = mode;
                                    mode |= 0o200 as libc::c_int as libc::c_uint;
                                    ofd = libc::open(
                                        np,
                                        0o1 as libc::c_int | 0o100 as libc::c_int,
                                        mode,
                                    );
                                    if ofd == -(1 as libc::c_int) {
                                        current_block = 11551238854158739040;
                                    } else {
                                        atomicio(
                                            ::core::mem::transmute::<
                                                Option<
                                                    unsafe extern "C" fn(
                                                        libc::c_int,
                                                        *const libc::c_void,
                                                        size_t,
                                                    )
                                                        -> ssize_t,
                                                >,
                                                Option<
                                                    unsafe extern "C" fn(
                                                        libc::c_int,
                                                        *mut libc::c_void,
                                                        size_t,
                                                    )
                                                        -> ssize_t,
                                                >,
                                            >(Some(
                                                write
                                                    as unsafe extern "C" fn(
                                                        libc::c_int,
                                                        *const libc::c_void,
                                                        size_t,
                                                    )
                                                        -> ssize_t,
                                            )),
                                            remout,
                                            b"\0" as *const u8 as *const libc::c_char
                                                as *mut libc::c_void,
                                            1 as libc::c_int as size_t,
                                        );
                                        bp = allocbuf(&mut buffer, ofd, 16384 as libc::c_int);
                                        if bp.is_null() {
                                            close(ofd);
                                        } else {
                                            cp = (*bp).buf;
                                            wrerr = 0 as libc::c_int;
                                            statbytes = 0 as libc::c_int as off_t;
                                            if showprogress != 0 {
                                                start_progress_meter(curfile, size, &mut statbytes);
                                            }
                                            crate::misc::set_nonblock(remin);
                                            i = 0 as libc::c_int as off_t;
                                            count = i as size_t;
                                            while i < size {
                                                amt = (*bp).cnt as libc::c_int;
                                                if i + amt as libc::c_long > size {
                                                    amt = (size - i) as libc::c_int;
                                                }
                                                count = (count as libc::c_ulong)
                                                    .wrapping_add(amt as libc::c_ulong)
                                                    as size_t
                                                    as size_t;
                                                loop {
                                                    j = atomicio6(
                                                        Some(
                                                            read
                                                                as unsafe extern "C" fn(
                                                                    libc::c_int,
                                                                    *mut libc::c_void,
                                                                    size_t,
                                                                ) -> ssize_t,
                                                        ),
                                                        remin,
                                                        cp as *mut libc::c_void,
                                                        amt as size_t,
                                                        Some(
                                                            scpio
                                                                as unsafe extern "C" fn(
                                                                    *mut libc::c_void,
                                                                    size_t,
                                                                ) -> libc::c_int,
                                                        ),
                                                        &mut statbytes as *mut off_t as *mut libc::c_void,
                                                    );
                                                    if j == 0 as libc::c_int as libc::c_ulong {
                                                        run_err(
                                                            b"%s\0" as *const u8
                                                                as *const libc::c_char,
                                                            if j != 32 as libc::c_int
                                                                as libc::c_ulong
                                                            {
                                                                strerror(*libc::__errno_location())
                                                                    as *const libc::c_char
                                                            } else {
                                                                b"dropped connection\0" as *const u8
                                                                    as *const libc::c_char
                                                            },
                                                        );
                                                        libc::exit(1 as libc::c_int);
                                                    }
                                                    amt = (amt as libc::c_ulong).wrapping_sub(j)
                                                        as libc::c_int
                                                        as libc::c_int;
                                                    cp = cp.offset(j as isize);
                                                    if !(amt > 0 as libc::c_int) {
                                                        break;
                                                    }
                                                }
                                                if count == (*bp).cnt {
                                                    if wrerr == 0 {
                                                        if atomicio(
                                                            ::core::mem::transmute::<
                                                                Option::<
                                                                    unsafe extern "C" fn(
                                                                        libc::c_int,
                                                                        *const libc::c_void,
                                                                        size_t,
                                                                    ) -> ssize_t,
                                                                >,
                                                                Option::<
                                                                    unsafe extern "C" fn(
                                                                        libc::c_int,
                                                                        *mut libc::c_void,
                                                                        size_t,
                                                                    ) -> ssize_t,
                                                                >,
                                                            >(
                                                                Some(
                                                                    write
                                                                        as unsafe extern "C" fn(
                                                                            libc::c_int,
                                                                            *const libc::c_void,
                                                                            size_t,
                                                                        ) -> ssize_t,
                                                                ),
                                                            ),
                                                            ofd,
                                                            (*bp).buf as *mut libc::c_void,
                                                            count,
                                                        ) != count
                                                        {
                                                            note_err(
                                                                b"%s: %s\0" as *const u8 as *const libc::c_char,
                                                                np,
                                                                strerror(*libc::__errno_location()),
                                                            );
                                                            wrerr = 1 as libc::c_int;
                                                        }
                                                    }
                                                    count = 0 as libc::c_int as size_t;
                                                    cp = (*bp).buf;
                                                }
                                                i = (i as libc::c_ulong).wrapping_add((*bp).cnt)
                                                    as off_t
                                                    as off_t;
                                            }
                                            crate::misc::unset_nonblock(remin);
                                            if count != 0 as libc::c_int as libc::c_ulong
                                                && wrerr == 0
                                                && atomicio(
                                                    ::core::mem::transmute::<
                                                        Option<
                                                            unsafe extern "C" fn(
                                                                libc::c_int,
                                                                *const libc::c_void,
                                                                size_t,
                                                            )
                                                                -> ssize_t,
                                                        >,
                                                        Option<
                                                            unsafe extern "C" fn(
                                                                libc::c_int,
                                                                *mut libc::c_void,
                                                                size_t,
                                                            )
                                                                -> ssize_t,
                                                        >,
                                                    >(
                                                        Some(
                                                            write
                                                                as unsafe extern "C" fn(
                                                                    libc::c_int,
                                                                    *const libc::c_void,
                                                                    size_t,
                                                                )
                                                                    -> ssize_t,
                                                        ),
                                                    ),
                                                    ofd,
                                                    (*bp).buf as *mut libc::c_void,
                                                    count,
                                                ) != count
                                            {
                                                note_err(
                                                    b"%s: %s\0" as *const u8 as *const libc::c_char,
                                                    np,
                                                    strerror(*libc::__errno_location()),
                                                );
                                                wrerr = 1 as libc::c_int;
                                            }
                                            if wrerr == 0
                                                && (exists == 0
                                                    || stb.st_mode
                                                        & 0o170000 as libc::c_int as libc::c_uint
                                                        == 0o100000 as libc::c_int as libc::c_uint)
                                                && libc::ftruncate(ofd, size) != 0 as libc::c_int
                                            {
                                                note_err(
                                                    b"%s: truncate: %s\0" as *const u8
                                                        as *const libc::c_char,
                                                    np,
                                                    strerror(*libc::__errno_location()),
                                                );
                                            }
                                            if pflag != 0 {
                                                if exists != 0 || omode != mode {
                                                    if libc::fchmod(ofd, omode) != 0 {
                                                        note_err(
                                                            b"%s: set mode: %s\0" as *const u8
                                                                as *const libc::c_char,
                                                            np,
                                                            strerror(*libc::__errno_location()),
                                                        );
                                                    }
                                                }
                                            } else if exists == 0 && omode != mode {
                                                if libc::fchmod(ofd, omode & !mask) != 0 {
                                                    note_err(
                                                        b"%s: set mode: %s\0" as *const u8
                                                            as *const libc::c_char,
                                                        np,
                                                        strerror(*libc::__errno_location()),
                                                    );
                                                }
                                            }
                                            if close(ofd) == -(1 as libc::c_int) {
                                                note_err(
                                                    b"%s: close: %s\0" as *const u8
                                                        as *const libc::c_char,
                                                    np,
                                                    strerror(*libc::__errno_location()),
                                                );
                                            }
                                            response();
                                            if showprogress != 0 {
                                                stop_progress_meter();
                                            }
                                            if setimes != 0 && wrerr == 0 {
                                                setimes = 0 as libc::c_int;
                                                if libc::utimes(
                                                    np,
                                                    tv.as_mut_ptr() as *const libc::timeval,
                                                ) == -(1 as libc::c_int)
                                                {
                                                    note_err(
                                                        b"%s: set times: %s\0" as *const u8
                                                            as *const libc::c_char,
                                                        np,
                                                        strerror(*libc::__errno_location()),
                                                    );
                                                }
                                            }
                                            if note_err(0 as *const libc::c_char)
                                                == 0 as libc::c_int
                                            {
                                                atomicio(
                                                    ::core::mem::transmute::<
                                                        Option<
                                                            unsafe extern "C" fn(
                                                                libc::c_int,
                                                                *const libc::c_void,
                                                                size_t,
                                                            )
                                                                -> ssize_t,
                                                        >,
                                                        Option<
                                                            unsafe extern "C" fn(
                                                                libc::c_int,
                                                                *mut libc::c_void,
                                                                size_t,
                                                            )
                                                                -> ssize_t,
                                                        >,
                                                    >(
                                                        Some(
                                                            write
                                                                as unsafe extern "C" fn(
                                                                    libc::c_int,
                                                                    *const libc::c_void,
                                                                    size_t,
                                                                )
                                                                    -> ssize_t,
                                                        ),
                                                    ),
                                                    remout,
                                                    b"\0" as *const u8 as *const libc::c_char
                                                        as *mut libc::c_void,
                                                    1 as libc::c_int as size_t,
                                                );
                                            }
                                        }
                                        current_block = 5783071609795492627;
                                    }
                                }
                                match current_block {
                                    5783071609795492627 => {}
                                    _ => {
                                        run_err(
                                            b"%s: %s\0" as *const u8 as *const libc::c_char,
                                            np,
                                            strerror(*libc::__errno_location()),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                first = 0 as libc::c_int;
            }
        }
        match current_block {
            2582807901502089632 => {}
            _ => {
                n = 0 as libc::c_int as size_t;
                while n < npatterns {
                    libc::free(*patterns.offset(n as isize) as *mut libc::c_void);
                    n = n.wrapping_add(1);
                    n;
                }
                libc::free(patterns as *mut libc::c_void);
                return;
            }
        }
    }
    n = 0 as libc::c_int as size_t;
    while n < npatterns {
        libc::free(*patterns.offset(n as isize) as *mut libc::c_void);
        n = n.wrapping_add(1);
        n;
    }
    libc::free(patterns as *mut libc::c_void);
    run_err(
        b"protocol error: %s\0" as *const u8 as *const libc::c_char,
        why,
    );
    libc::exit(1 as libc::c_int);
}
pub unsafe extern "C" fn throughlocal_sftp(
    mut from: *mut sftp_conn,
    mut to: *mut sftp_conn,
    mut src: *mut libc::c_char,
    mut targ: *mut libc::c_char,
) {
    let mut current_block: u64;
    let mut target: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut abs_dst: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut abs_src: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut g: _ssh_compat_glob_t = _ssh_compat_glob_t {
        gl_pathc: 0,
        gl_matchc: 0,
        gl_offs: 0,
        gl_flags: 0,
        gl_pathv: 0 as *mut *mut libc::c_char,
        gl_statv: 0 as *mut *mut libc::stat,
        gl_errfunc: None,
        gl_closedir: None,
        gl_readdir: None,
        gl_opendir: None,
        gl_lstat: None,
        gl_stat: None,
    };
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut targetisdir: libc::c_int = 0;
    let mut err: libc::c_int = 0 as libc::c_int;
    filename = __xpg_basename(src);
    if filename.is_null() {
        sshfatal(
            b"scp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"throughlocal_sftp\0"))
                .as_ptr(),
            1984 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"basename %s: %s\0" as *const u8 as *const libc::c_char,
            src,
            strerror(*libc::__errno_location()),
        );
    }
    abs_src = prepare_remote_path(from, src);
    if abs_src.is_null() || {
        target = prepare_remote_path(to, targ);
        target.is_null()
    } {
        cleanup_exit(255 as libc::c_int);
    }
    memset(
        &mut g as *mut _ssh_compat_glob_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<_ssh_compat_glob_t>() as libc::c_ulong,
    );
    targetisdir = remote_is_dir(to, target);
    if targetisdir == 0 && targetshouldbedirectory != 0 {
        crate::log::sshlog(
            b"scp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"throughlocal_sftp\0"))
                .as_ptr(),
            1993 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s: destination is not a directory\0" as *const u8 as *const libc::c_char,
            targ,
        );
        err = -(1 as libc::c_int);
    } else {
        crate::log::sshlog(
            b"scp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"throughlocal_sftp\0"))
                .as_ptr(),
            1998 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"copying remote %s to remote %s\0" as *const u8 as *const libc::c_char,
            abs_src,
            target,
        );
        r = remote_glob(
            from,
            abs_src,
            0x10 as libc::c_int | 0x8 as libc::c_int,
            None,
            &mut g,
        );
        if r != 0 as libc::c_int {
            if r == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"scp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"throughlocal_sftp\0",
                    ))
                    .as_ptr(),
                    2002 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s: too many glob matches\0" as *const u8 as *const libc::c_char,
                    src,
                );
            } else {
                crate::log::sshlog(
                    b"scp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"throughlocal_sftp\0",
                    ))
                    .as_ptr(),
                    2004 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s: %s\0" as *const u8 as *const libc::c_char,
                    src,
                    strerror(2 as libc::c_int),
                );
            }
            err = -(1 as libc::c_int);
        } else {
            if g.gl_matchc == 0 as libc::c_int as libc::c_ulong
                && g.gl_pathc == 1 as libc::c_int as libc::c_ulong
                && !(*(g.gl_pathv).offset(0 as libc::c_int as isize)).is_null()
            {
                if (do_stat(
                    from,
                    *(g.gl_pathv).offset(0 as libc::c_int as isize),
                    1 as libc::c_int,
                ))
                .is_null()
                {
                    crate::log::sshlog(
                        b"scp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                            b"throughlocal_sftp\0",
                        ))
                        .as_ptr(),
                        2017 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s: %s\0" as *const u8 as *const libc::c_char,
                        src,
                        strerror(2 as libc::c_int),
                    );
                    err = -(1 as libc::c_int);
                    current_block = 16037846890308690790;
                } else {
                    current_block = 4956146061682418353;
                }
            } else {
                current_block = 4956146061682418353;
            }
            match current_block {
                16037846890308690790 => {}
                _ => {
                    i = 0 as libc::c_int;
                    while !(*(g.gl_pathv).offset(i as isize)).is_null() && interrupted == 0 {
                        tmp = xstrdup(*(g.gl_pathv).offset(i as isize));
                        filename = __xpg_basename(tmp);
                        if filename.is_null() {
                            crate::log::sshlog(
                                b"scp.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                                    b"throughlocal_sftp\0",
                                ))
                                .as_ptr(),
                                2026 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"basename %s: %s\0" as *const u8 as *const libc::c_char,
                                tmp,
                                strerror(*libc::__errno_location()),
                            );
                            err = -(1 as libc::c_int);
                            break;
                        } else {
                            if targetisdir != 0 {
                                abs_dst = path_append(target, filename);
                            } else {
                                abs_dst = xstrdup(target);
                            }
                            crate::log::sshlog(
                                b"scp.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                                    b"throughlocal_sftp\0",
                                ))
                                .as_ptr(),
                                2036 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG1,
                                0 as *const libc::c_char,
                                b"Fetching %s to %s\n\0" as *const u8 as *const libc::c_char,
                                *(g.gl_pathv).offset(i as isize),
                                abs_dst,
                            );
                            if globpath_is_dir(*(g.gl_pathv).offset(i as isize)) != 0
                                && iamrecursive != 0
                            {
                                if crossload_dir(
                                    from,
                                    to,
                                    *(g.gl_pathv).offset(i as isize),
                                    abs_dst,
                                    0 as *mut Attrib,
                                    pflag,
                                    2 as libc::c_int,
                                    1 as libc::c_int,
                                ) == -(1 as libc::c_int)
                                {
                                    err = -(1 as libc::c_int);
                                }
                            } else if do_crossload(
                                from,
                                to,
                                *(g.gl_pathv).offset(i as isize),
                                abs_dst,
                                0 as *mut Attrib,
                                pflag,
                            ) == -(1 as libc::c_int)
                            {
                                err = -(1 as libc::c_int);
                            }
                            libc::free(abs_dst as *mut libc::c_void);
                            abs_dst = 0 as *mut libc::c_char;
                            libc::free(tmp as *mut libc::c_void);
                            tmp = 0 as *mut libc::c_char;
                            i += 1;
                            i;
                        }
                    }
                }
            }
        }
    }
    libc::free(abs_src as *mut libc::c_void);
    libc::free(abs_dst as *mut libc::c_void);
    libc::free(target as *mut libc::c_void);
    libc::free(tmp as *mut libc::c_void);
    _ssh__compat_globfree(&mut g);
    if err == -(1 as libc::c_int) {
        errs = 1 as libc::c_int;
    }
}
pub unsafe extern "C" fn response() -> libc::c_int {
    let mut ch: libc::c_char = 0;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut resp: libc::c_char = 0;
    let mut rbuf: [libc::c_char; 2048] = [0; 2048];
    let mut visbuf: [libc::c_char; 2048] = [0; 2048];
    if atomicio(
        Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
        remin,
        &mut resp as *mut libc::c_char as *mut libc::c_void,
        ::core::mem::size_of::<libc::c_char>() as libc::c_ulong,
    ) != ::core::mem::size_of::<libc::c_char>() as libc::c_ulong
    {
        lostconn(0 as libc::c_int);
    }
    cp = rbuf.as_mut_ptr();
    match resp as libc::c_int {
        0 => return 0 as libc::c_int,
        1 | 2 => {}
        _ => {
            let fresh11 = cp;
            cp = cp.offset(1);
            *fresh11 = resp;
        }
    }
    loop {
        if atomicio(
            Some(read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t),
            remin,
            &mut ch as *mut libc::c_char as *mut libc::c_void,
            ::core::mem::size_of::<libc::c_char>() as libc::c_ulong,
        ) != ::core::mem::size_of::<libc::c_char>() as libc::c_ulong
        {
            lostconn(0 as libc::c_int);
        }
        let fresh12 = cp;
        cp = cp.offset(1);
        *fresh12 = ch;
        if !(cp
            < &mut *rbuf.as_mut_ptr().offset(
                (::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
            ) as *mut libc::c_char
            && ch as libc::c_int != '\n' as i32)
        {
            break;
        }
    }
    if iamremote == 0 {
        *cp.offset(-(1 as libc::c_int) as isize) = '\0' as i32 as libc::c_char;
        snmprintf(
            visbuf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong,
            0 as *mut libc::c_int,
            b"%s\n\0" as *const u8 as *const libc::c_char,
            rbuf.as_mut_ptr(),
        );
        atomicio(
            ::core::mem::transmute::<
                Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
                Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
            >(Some(
                write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
            )),
            2 as libc::c_int,
            visbuf.as_mut_ptr() as *mut libc::c_void,
            strlen(visbuf.as_mut_ptr()),
        );
    }
    errs += 1;
    errs;
    if resp as libc::c_int == 1 as libc::c_int {
        return -(1 as libc::c_int);
    }
    libc::exit(1 as libc::c_int);
}
pub unsafe extern "C" fn usage() {
    libc::fprintf(
        stderr,
        b"usage: scp [-346ABCOpqRrsTv] [-c cipher] [-D sftp_server_path] [-F ssh_config]\n           [-i identity_file] [-J destination] [-l limit] [-o ssh_option]\n           [-P port] [-S program] [-X sftp_option] source ... target\n\0"
            as *const u8 as *const libc::c_char,
    );
    libc::exit(1 as libc::c_int);
}
pub unsafe extern "C" fn run_err(mut fmt: *const libc::c_char, mut args_0: ...) {
    static mut fp: *mut libc::FILE = 0 as *const libc::FILE as *mut libc::FILE;
    let mut ap: ::core::ffi::VaListImpl;
    errs += 1;
    errs;
    if !fp.is_null()
        || remout != -(1 as libc::c_int) && {
            fp = libc::fdopen(remout, b"w\0" as *const u8 as *const libc::c_char);
            !fp.is_null()
        }
    {
        libc::fprintf(
            fp,
            b"%c\0" as *const u8 as *const libc::c_char,
            0x1 as libc::c_int,
        );
        libc::fprintf(fp, b"scp: \0" as *const u8 as *const libc::c_char);
        ap = args_0.clone();
        vfprintf(fp, fmt, ap.as_va_list());
        libc::fprintf(fp, b"\n\0" as *const u8 as *const libc::c_char);
        libc::fflush(fp);
    }
    if iamremote == 0 {
        ap = args_0.clone();
        vfmprintf(stderr, fmt, ap.as_va_list());
        libc::fprintf(stderr, b"\n\0" as *const u8 as *const libc::c_char);
    }
}
pub unsafe extern "C" fn note_err(mut fmt: *const libc::c_char, mut args_0: ...) -> libc::c_int {
    static mut emsg: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
    let mut ap: ::core::ffi::VaListImpl;
    if fmt.is_null() {
        if emsg.is_null() {
            return 0 as libc::c_int;
        }
        run_err(b"%s\0" as *const u8 as *const libc::c_char, emsg);
        libc::free(emsg as *mut libc::c_void);
        emsg = 0 as *mut libc::c_char;
        return -(1 as libc::c_int);
    }
    errs += 1;
    errs;
    if !emsg.is_null() {
        return -(1 as libc::c_int);
    }
    ap = args_0.clone();
    vasnmprintf(
        &mut emsg,
        2147483647 as libc::c_int as size_t,
        0 as *mut libc::c_int,
        fmt,
        ap.as_va_list(),
    );
    return -(1 as libc::c_int);
}
pub unsafe extern "C" fn verifydir(mut cp: *mut libc::c_char) {
    let mut stb: libc::stat = unsafe { std::mem::zeroed() };
    if libc::stat(cp, &mut stb) == 0 {
        if stb.st_mode & 0o170000 as libc::c_int as libc::c_uint
            == 0o40000 as libc::c_int as libc::c_uint
        {
            return;
        }
        *libc::__errno_location() = 20 as libc::c_int;
    }
    run_err(
        b"%s: %s\0" as *const u8 as *const libc::c_char,
        cp,
        strerror(*libc::__errno_location()),
    );
    killchild(0 as libc::c_int);
}
pub unsafe extern "C" fn okname(mut cp0: *mut libc::c_char) -> libc::c_int {
    let mut current_block: u64;
    let mut c: libc::c_int = 0;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    cp = cp0;
    loop {
        c = *cp as libc::c_int;
        if c & 0o200 as libc::c_int != 0 {
            current_block = 14257875744943665969;
            break;
        }
        if *(*__ctype_b_loc()).offset(c as isize) as libc::c_int
            & _ISalpha as libc::c_int as libc::c_ushort as libc::c_int
            == 0
            && *(*__ctype_b_loc()).offset(c as libc::c_uchar as libc::c_int as isize) as libc::c_int
                & _ISdigit as libc::c_int as libc::c_ushort as libc::c_int
                == 0
        {
            match c {
                39 | 34 | 96 | 32 | 35 => {
                    current_block = 14257875744943665969;
                    break;
                }
                _ => {}
            }
        }
        cp = cp.offset(1);
        if !(*cp != 0) {
            current_block = 13513818773234778473;
            break;
        }
    }
    match current_block {
        13513818773234778473 => return 1 as libc::c_int,
        _ => {
            fmprintf(
                stderr,
                b"%s: invalid user name\n\0" as *const u8 as *const libc::c_char,
                cp0,
            );
            return 0 as libc::c_int;
        }
    };
}
pub unsafe extern "C" fn allocbuf(
    mut bp: *mut BUF,
    mut fd: libc::c_int,
    mut blksize: libc::c_int,
) -> *mut BUF {
    let mut size: size_t = 0;
    let mut stb: libc::stat = unsafe { std::mem::zeroed() };
    if libc::fstat(fd, &mut stb) == -(1 as libc::c_int) {
        run_err(
            b"libc::fstat: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
        return 0 as *mut BUF;
    }
    size = ((stb.st_blksize + (blksize - 1 as libc::c_int) as libc::c_long)
        / blksize as libc::c_long
        * blksize as libc::c_long) as size_t;
    if size == 0 as libc::c_int as libc::c_ulong {
        size = blksize as size_t;
    }
    if (*bp).cnt >= size {
        return bp;
    }
    (*bp).buf = xrecallocarray(
        (*bp).buf as *mut libc::c_void,
        (*bp).cnt,
        size,
        1 as libc::c_int as size_t,
    ) as *mut libc::c_char;
    (*bp).cnt = size;
    return bp;
}
pub unsafe extern "C" fn lostconn(mut signo: libc::c_int) {
    if iamremote == 0 {
        write(
            2 as libc::c_int,
            b"lost connection\n\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            16 as libc::c_int as size_t,
        );
    }
    if signo != 0 {
        libc::_exit(1 as libc::c_int);
    } else {
        libc::exit(1 as libc::c_int);
    };
}
pub unsafe extern "C" fn cleanup_exit(mut i: libc::c_int) -> ! {
    if remin > 0 as libc::c_int {
        close(remin);
    }
    if remout > 0 as libc::c_int {
        close(remout);
    }
    if remin2 > 0 as libc::c_int {
        close(remin2);
    }
    if remout2 > 0 as libc::c_int {
        close(remout2);
    }
    if do_cmd_pid > 0 as libc::c_int {
        libc::waitpid(do_cmd_pid, 0 as *mut libc::c_int, 0 as libc::c_int);
    }
    if do_cmd_pid2 > 0 as libc::c_int {
        libc::waitpid(do_cmd_pid2, 0 as *mut libc::c_int, 0 as libc::c_int);
    }
    libc::exit(i);
}
pub fn main() {
    let mut args_x: Vec<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args_x.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args_x.push(::core::ptr::null_mut());
    unsafe {
        ::std::process::exit(main_0(
            (args_x.len() - 1) as libc::c_int,
            args_x.as_mut_ptr() as *mut *mut libc::c_char,
        ) as i32)
    }
}
