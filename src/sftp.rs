use crate::log::log_init;
use crate::misc::arglist;
use crate::misc::parse_uri;
use crate::misc::parse_user_host_path;
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
use crate::utf8::msetlocale;
use ::libc;
use libc::close;
use libc::kill;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type dirent;

    fn shutdown(__fd: libc::c_int, __how: libc::c_int) -> libc::c_int;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn sigaction(
        __sig: libc::c_int,
        __act: *const sigaction,
        __oact: *mut sigaction,
    ) -> libc::c_int;

    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn chdir(__path: *const libc::c_char) -> libc::c_int;
    fn getcwd(__buf: *mut libc::c_char, __size: size_t) -> *mut libc::c_char;

    fn execl(__path: *const libc::c_char, __arg: *const libc::c_char, _: ...) -> libc::c_int;
    fn execvp(__file: *const libc::c_char, __argv: *const *mut libc::c_char) -> libc::c_int;

    
    
    
    fn isatty(__fd: libc::c_int) -> libc::c_int;
    static mut BSDoptarg: *mut libc::c_char;
    static mut BSDoptind: libc::c_int;
    static mut BSDopterr: libc::c_int;
    static mut BSDoptopt: libc::c_int;
    fn BSDgetopt(
        ___argc: libc::c_int,
        ___argv: *const *mut libc::c_char,
        __shortopts: *const libc::c_char,
    ) -> libc::c_int;
    static mut stdin: *mut libc::FILE;
    static mut stdout: *mut libc::FILE;
    static mut stderr: *mut libc::FILE;
    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::FILE;
    fn setvbuf(
        __stream: *mut libc::FILE,
        __buf: *mut libc::c_char,
        __modes: libc::c_int,
        __n: size_t,
    ) -> libc::c_int;

    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;

    fn fgets(
        __s: *mut libc::c_char,
        __n: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> *mut libc::c_char;
    fn fileno(__stream: *mut libc::FILE) -> libc::c_int;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn fmt_scaled(number: libc::c_longlong, result: *mut libc::c_char) -> libc::c_int;
    fn scan_scaled(_: *mut libc::c_char, _: *mut libc::c_longlong) -> libc::c_int;
    static mut BSDoptreset: libc::c_int;

    fn ioctl(__fd: libc::c_int, __request: libc::c_ulong, _: ...) -> libc::c_int;

    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    fn __xpg_basename(__path: *mut libc::c_char) -> *mut libc::c_char;
    fn strtol(_: *const libc::c_char, _: *mut *mut libc::c_char, _: libc::c_int) -> libc::c_long;
    fn strtoll(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_longlong;

    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn qsort(__base: *mut libc::c_void, __nmemb: size_t, __size: size_t, __compar: __compar_fn_t);
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn strsignal(__sig: libc::c_int) -> *mut libc::c_char;
    fn xmalloc(_: size_t) -> *mut libc::c_void;
    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;

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
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;

    fn cleanhostname(_: *mut libc::c_char) -> *mut libc::c_char;

    fn parse_user_host_port(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: *mut *mut libc::c_char,
        _: *mut libc::c_int,
    ) -> libc::c_int;

    fn tilde_expand_filename(_: *const libc::c_char, _: uid_t) -> *mut libc::c_char;

    fn path_absolute(_: *const libc::c_char) -> libc::c_int;

    fn argv_split(
        _: *const libc::c_char,
        _: *mut libc::c_int,
        _: *mut *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn argv_free(_: *mut *mut libc::c_char, _: libc::c_int);
    fn ssh_signal(_: libc::c_int, _: sshsig_t) -> sshsig_t;
    fn mprintf(_: *const libc::c_char, _: ...) -> libc::c_int;

    fn attrib_clear(_: *mut Attrib);
    fn attrib_to_stat(_: *const Attrib, _: *mut libc::stat);
    fn ls_file(
        _: *const libc::c_char,
        _: *const libc::stat,
        _: libc::c_int,
        _: libc::c_int,
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> *mut libc::c_char;

    fn sftp_proto_version(_: *mut sftp_conn) -> u_int;
    fn do_readdir(
        _: *mut sftp_conn,
        _: *const libc::c_char,
        _: *mut *mut *mut SFTP_DIRENT,
    ) -> libc::c_int;
    fn free_sftp_dirents(_: *mut *mut SFTP_DIRENT);
    fn do_rm(_: *mut sftp_conn, _: *const libc::c_char) -> libc::c_int;

    fn do_rmdir(_: *mut sftp_conn, _: *const libc::c_char) -> libc::c_int;

    fn do_lstat(_: *mut sftp_conn, _: *const libc::c_char, _: libc::c_int) -> *mut Attrib;
    fn do_setstat(_: *mut sftp_conn, _: *const libc::c_char, _: *mut Attrib) -> libc::c_int;
    fn do_lsetstat(conn: *mut sftp_conn, path: *const libc::c_char, a: *mut Attrib) -> libc::c_int;
    fn do_realpath(_: *mut sftp_conn, _: *const libc::c_char) -> *mut libc::c_char;
    fn do_statvfs(
        _: *mut sftp_conn,
        _: *const libc::c_char,
        _: *mut sftp_statvfs,
        _: libc::c_int,
    ) -> libc::c_int;
    fn do_rename(
        _: *mut sftp_conn,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn do_copy(_: *mut sftp_conn, _: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn do_symlink(_: *mut sftp_conn, _: *const libc::c_char, _: *const libc::c_char)
        -> libc::c_int;
    fn make_absolute(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn do_hardlink(
        _: *mut sftp_conn,
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> libc::c_int;

    fn can_get_users_groups_by_id(conn: *mut sftp_conn) -> libc::c_int;

    fn local_is_dir(path: *const libc::c_char) -> libc::c_int;

    fn _ssh__compat_glob(
        _: *const libc::c_char,
        _: libc::c_int,
        _: Option<unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> libc::c_int>,
        _: *mut _ssh_compat_glob_t,
    ) -> libc::c_int;
    fn _ssh__compat_globfree(_: *mut _ssh_compat_glob_t);
    fn get_remote_user_groups_from_glob(conn: *mut sftp_conn, g: *mut _ssh_compat_glob_t);
    fn get_remote_user_groups_from_dirents(conn: *mut sftp_conn, d: *mut *mut SFTP_DIRENT);
    fn ruser_name(uid: uid_t) -> *const libc::c_char;
    fn rgroup_name(gid: uid_t) -> *const libc::c_char;
    fn remote_glob(
        _: *mut sftp_conn,
        _: *const libc::c_char,
        _: libc::c_int,
        _: Option<unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> libc::c_int>,
        _: *mut _ssh_compat_glob_t,
    ) -> libc::c_int;
    static mut __progname: *mut libc::c_char;
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
pub type __clock_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __sig_atomic_t = libc::c_int;
pub type u_int = __u_int;
pub type uid_t = __uid_t;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __sigset_t {
    pub __val: [libc::c_ulong; 16],
}

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
pub type C2RustUnnamed = libc::c_uint;
pub const SHUT_RDWR: C2RustUnnamed = 2;
pub const SHUT_WR: C2RustUnnamed = 1;
pub const SHUT_RD: C2RustUnnamed = 0;

pub type _IO_lock_t = ();

pub type sig_atomic_t = __sig_atomic_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub union sigval {
    pub sival_int: libc::c_int,
    pub sival_ptr: *mut libc::c_void,
}
pub type __sigval_t = sigval;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct siginfo_t {
    pub si_signo: libc::c_int,
    pub si_errno: libc::c_int,
    pub si_code: libc::c_int,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sigaction {
    pub __sigaction_handler: C2RustUnnamed_10,
    pub sa_mask: __sigset_t,
    pub sa_flags: libc::c_int,
    pub sa_restorer: Option<unsafe extern "C" fn() -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_10 {
    pub sa_handler: __sighandler_t,
    pub sa_sigaction:
        Option<unsafe extern "C" fn(libc::c_int, *mut siginfo_t, *mut libc::c_void) -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct winsize {
    pub ws_row: libc::c_ushort,
    pub ws_col: libc::c_ushort,
    pub ws_xpixel: libc::c_ushort,
    pub ws_ypixel: libc::c_ushort,
}
pub type C2RustUnnamed_11 = libc::c_uint;
pub const _ISalnum: C2RustUnnamed_11 = 8;
pub const _ISpunct: C2RustUnnamed_11 = 4;
pub const _IScntrl: C2RustUnnamed_11 = 2;
pub const _ISblank: C2RustUnnamed_11 = 1;
pub const _ISgraph: C2RustUnnamed_11 = 32768;
pub const _ISprint: C2RustUnnamed_11 = 16384;
pub const _ISspace: C2RustUnnamed_11 = 8192;
pub const _ISxdigit: C2RustUnnamed_11 = 4096;
pub const _ISdigit: C2RustUnnamed_11 = 2048;
pub const _ISalpha: C2RustUnnamed_11 = 1024;
pub const _ISlower: C2RustUnnamed_11 = 512;
pub const _ISupper: C2RustUnnamed_11 = 256;
pub type EditLine = ();
pub type __compar_fn_t =
    Option<unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int>;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct SFTP_DIRENT {
    pub filename: *mut libc::c_char,
    pub longname: *mut libc::c_char,
    pub a: Attrib,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sftp_statvfs {
    pub f_bsize: u_int64_t,
    pub f_frsize: u_int64_t,
    pub f_blocks: u_int64_t,
    pub f_bfree: u_int64_t,
    pub f_bavail: u_int64_t,
    pub f_files: u_int64_t,
    pub f_ffree: u_int64_t,
    pub f_favail: u_int64_t,
    pub f_fsid: u_int64_t,
    pub f_flag: u_int64_t,
    pub f_namemax: u_int64_t,
}
pub type sftp_command = libc::c_uint;
pub const I_PROGRESS: sftp_command = 28;
pub const I_VERSION: sftp_command = 27;
pub const I_SYMLINK: sftp_command = 26;
pub const I_SHELL: sftp_command = 25;
pub const I_RMDIR: sftp_command = 24;
pub const I_RM: sftp_command = 23;
pub const I_REPUT: sftp_command = 22;
pub const I_RENAME: sftp_command = 21;
pub const I_REGET: sftp_command = 20;
pub const I_QUIT: sftp_command = 19;
pub const I_PWD: sftp_command = 18;
pub const I_PUT: sftp_command = 17;
pub const I_MKDIR: sftp_command = 16;
pub const I_LUMASK: sftp_command = 15;
pub const I_LS: sftp_command = 14;
pub const I_LPWD: sftp_command = 13;
pub const I_LMKDIR: sftp_command = 12;
pub const I_LLS: sftp_command = 11;
pub const I_LINK: sftp_command = 10;
pub const I_LCHDIR: sftp_command = 9;
pub const I_HELP: sftp_command = 8;
pub const I_GET: sftp_command = 7;
pub const I_DF: sftp_command = 6;
pub const I_COPY: sftp_command = 5;
pub const I_CHOWN: sftp_command = 4;
pub const I_CHMOD: sftp_command = 3;
pub const I_CHGRP: sftp_command = 2;
pub const I_CHDIR: sftp_command = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct CMD {
    pub c: *const libc::c_char,
    pub n: libc::c_int,
    pub t: libc::c_int,
    pub t2: libc::c_int,
}
pub const MA_DQUOTE: C2RustUnnamed_12 = 2;
pub type C2RustUnnamed_12 = libc::c_uint;
pub const MA_UNQUOTED: C2RustUnnamed_12 = 3;
pub const MA_SQUOTE: C2RustUnnamed_12 = 1;
pub const MA_START: C2RustUnnamed_12 = 0;
pub static mut infile: *mut libc::FILE = 0 as *const libc::FILE as *mut libc::FILE;
pub static mut batchmode: libc::c_int = 0 as libc::c_int;
static mut sshpid: pid_t = -(1 as libc::c_int);
pub static mut quiet: libc::c_int = 0 as libc::c_int;
pub static mut showprogress: libc::c_int = 1 as libc::c_int;
pub static mut global_rflag: libc::c_int = 0 as libc::c_int;
pub static mut global_aflag: libc::c_int = 0 as libc::c_int;
pub static mut global_pflag: libc::c_int = 0 as libc::c_int;
pub static mut global_fflag: libc::c_int = 0 as libc::c_int;
pub static mut interrupted: sig_atomic_t = 0 as libc::c_int;
pub static mut sort_flag: libc::c_int = 0;
pub static mut sort_glob: *mut _ssh_compat_glob_t =
    0 as *const _ssh_compat_glob_t as *mut _ssh_compat_glob_t;
static mut cmds: [CMD; 38] = [
    {
        let mut init = CMD {
            c: b"bye\0" as *const u8 as *const libc::c_char,
            n: I_QUIT as libc::c_int,
            t: 0 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"cd\0" as *const u8 as *const libc::c_char,
            n: I_CHDIR as libc::c_int,
            t: 1 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"chdir\0" as *const u8 as *const libc::c_char,
            n: I_CHDIR as libc::c_int,
            t: 1 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"chgrp\0" as *const u8 as *const libc::c_char,
            n: I_CHGRP as libc::c_int,
            t: 1 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"chmod\0" as *const u8 as *const libc::c_char,
            n: I_CHMOD as libc::c_int,
            t: 1 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"chown\0" as *const u8 as *const libc::c_char,
            n: I_CHOWN as libc::c_int,
            t: 1 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"copy\0" as *const u8 as *const libc::c_char,
            n: I_COPY as libc::c_int,
            t: 1 as libc::c_int,
            t2: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"cp\0" as *const u8 as *const libc::c_char,
            n: I_COPY as libc::c_int,
            t: 1 as libc::c_int,
            t2: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"df\0" as *const u8 as *const libc::c_char,
            n: I_DF as libc::c_int,
            t: 1 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"dir\0" as *const u8 as *const libc::c_char,
            n: I_LS as libc::c_int,
            t: 1 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"libc::exit\0" as *const u8 as *const libc::c_char,
            n: I_QUIT as libc::c_int,
            t: 0 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"get\0" as *const u8 as *const libc::c_char,
            n: I_GET as libc::c_int,
            t: 1 as libc::c_int,
            t2: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"help\0" as *const u8 as *const libc::c_char,
            n: I_HELP as libc::c_int,
            t: 0 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"lcd\0" as *const u8 as *const libc::c_char,
            n: I_LCHDIR as libc::c_int,
            t: 2 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"lchdir\0" as *const u8 as *const libc::c_char,
            n: I_LCHDIR as libc::c_int,
            t: 2 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"lls\0" as *const u8 as *const libc::c_char,
            n: I_LLS as libc::c_int,
            t: 2 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"lmkdir\0" as *const u8 as *const libc::c_char,
            n: I_LMKDIR as libc::c_int,
            t: 2 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"ln\0" as *const u8 as *const libc::c_char,
            n: I_LINK as libc::c_int,
            t: 1 as libc::c_int,
            t2: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"lpwd\0" as *const u8 as *const libc::c_char,
            n: I_LPWD as libc::c_int,
            t: 2 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"ls\0" as *const u8 as *const libc::c_char,
            n: I_LS as libc::c_int,
            t: 1 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"lumask\0" as *const u8 as *const libc::c_char,
            n: I_LUMASK as libc::c_int,
            t: 0 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"mkdir\0" as *const u8 as *const libc::c_char,
            n: I_MKDIR as libc::c_int,
            t: 1 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"mget\0" as *const u8 as *const libc::c_char,
            n: I_GET as libc::c_int,
            t: 1 as libc::c_int,
            t2: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"mput\0" as *const u8 as *const libc::c_char,
            n: I_PUT as libc::c_int,
            t: 2 as libc::c_int,
            t2: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"progress\0" as *const u8 as *const libc::c_char,
            n: I_PROGRESS as libc::c_int,
            t: 0 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"put\0" as *const u8 as *const libc::c_char,
            n: I_PUT as libc::c_int,
            t: 2 as libc::c_int,
            t2: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"pwd\0" as *const u8 as *const libc::c_char,
            n: I_PWD as libc::c_int,
            t: 1 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"quit\0" as *const u8 as *const libc::c_char,
            n: I_QUIT as libc::c_int,
            t: 0 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"reget\0" as *const u8 as *const libc::c_char,
            n: I_REGET as libc::c_int,
            t: 1 as libc::c_int,
            t2: 2 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"rename\0" as *const u8 as *const libc::c_char,
            n: I_RENAME as libc::c_int,
            t: 1 as libc::c_int,
            t2: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"reput\0" as *const u8 as *const libc::c_char,
            n: I_REPUT as libc::c_int,
            t: 2 as libc::c_int,
            t2: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"rm\0" as *const u8 as *const libc::c_char,
            n: I_RM as libc::c_int,
            t: 1 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"rmdir\0" as *const u8 as *const libc::c_char,
            n: I_RMDIR as libc::c_int,
            t: 1 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"symlink\0" as *const u8 as *const libc::c_char,
            n: I_SYMLINK as libc::c_int,
            t: 1 as libc::c_int,
            t2: 1 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"version\0" as *const u8 as *const libc::c_char,
            n: I_VERSION as libc::c_int,
            t: 0 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"!\0" as *const u8 as *const libc::c_char,
            n: I_SHELL as libc::c_int,
            t: 0 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: b"?\0" as *const u8 as *const libc::c_char,
            n: I_HELP as libc::c_int,
            t: 0 as libc::c_int,
            t2: 0 as libc::c_int,
        };
        init
    },
    {
        let mut init = CMD {
            c: 0 as *const libc::c_char,
            n: -(1 as libc::c_int),
            t: -(1 as libc::c_int),
            t2: -(1 as libc::c_int),
        };
        init
    },
];
unsafe extern "C" fn killchild(mut _signo: libc::c_int) {
    let mut pid: pid_t = 0;
    pid = sshpid;
    if pid > 1 as libc::c_int {
        kill(pid, 15 as libc::c_int);
        libc::waitpid(pid, 0 as *mut libc::c_int, 0 as libc::c_int);
    }
    libc::_exit(1 as libc::c_int);
}
unsafe extern "C" fn suspchild(mut signo: libc::c_int) {
    if sshpid > 1 as libc::c_int {
        kill(sshpid, signo);
        while libc::waitpid(sshpid, 0 as *mut libc::c_int, 2 as libc::c_int) == -(1 as libc::c_int)
            && *libc::__errno_location() == 4 as libc::c_int
        {}
    }
    kill(libc::getpid(), 19 as libc::c_int);
}
unsafe extern "C" fn cmd_interrupt(mut _signo: libc::c_int) {
    let msg: [libc::c_char; 14] =
        *::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"\rInterrupt  \n\0");
    let mut olderrno: libc::c_int = *libc::__errno_location();
    write(
        2 as libc::c_int,
        msg.as_ptr() as *const libc::c_void,
        (::core::mem::size_of::<[libc::c_char; 14]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    );
    ::core::ptr::write_volatile(&mut interrupted as *mut sig_atomic_t, 1 as libc::c_int);
    *libc::__errno_location() = olderrno;
}
unsafe extern "C" fn read_interrupt(mut _signo: libc::c_int) {
    ::core::ptr::write_volatile(&mut interrupted as *mut sig_atomic_t, 1 as libc::c_int);
}
unsafe extern "C" fn sigchld_handler(mut _sig: libc::c_int) {
    let mut save_errno: libc::c_int = *libc::__errno_location();
    let mut pid: pid_t = 0;
    let msg: [libc::c_char; 23] =
        *::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"\rConnection closed.  \n\0");
    loop {
        pid = libc::waitpid(sshpid, 0 as *mut libc::c_int, 1 as libc::c_int);
        if !(pid == -(1 as libc::c_int) && *libc::__errno_location() == 4 as libc::c_int) {
            break;
        }
    }
    if pid == sshpid {
        if quiet == 0 {
            write(
                2 as libc::c_int,
                msg.as_ptr() as *const libc::c_void,
                (::core::mem::size_of::<[libc::c_char; 23]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            );
        }
        ::core::ptr::write_volatile(&mut sshpid as *mut pid_t, -(1 as libc::c_int));
    }
    *libc::__errno_location() = save_errno;
}
unsafe extern "C" fn help() {
    printf(
        b"Available commands:\nbye                                Quit sftp\ncd path                            Change remote directory to 'path'\nchgrp [-h] grp path                Change group of file 'path' to 'grp'\nchmod [-h] mode path               Change permissions of file 'path' to 'mode'\nchown [-h] own path                Change owner of file 'path' to 'own'\ncopy oldpath newpath               Copy remote file\ncp oldpath newpath                 Copy remote file\ndf [-hi] [path]                    Display statistics for current directory or\n                                   filesystem containing 'path'\nexit                               Quit sftp\nget [-afpR] remote [local]         Download file\nhelp                               Display this help text\nlcd path                           Change local directory to 'path'\nlls [ls-options [path]]            Display local directory listing\nlmkdir path                        Create local directory\nln [-s] oldpath newpath            Link remote file (-s for symlink)\nlpwd                               Print local working directory\nls [-1afhlnrSt] [path]             Display remote directory listing\nlumask umask                       Set local umask to 'umask'\nmkdir path                         Create remote directory\nprogress                           Toggle display of progress meter\nput [-afpR] local [remote]         Upload file\npwd                                Display remote working directory\nquit                               Quit sftp\nreget [-fpR] remote [local]        Resume download file\nrename oldpath newpath             Rename remote file\nreput [-fpR] local [remote]        Resume upload file\nrm path                            Delete remote file\nrmdir path                         Remove remote directory\nsymlink oldpath newpath            Symlink remote file\nversion                            Show SFTP version\n!command                           Execute 'command' in local shell\n!                                  Escape to local shell\n?                                  Synonym for help\n\0"
            as *const u8 as *const libc::c_char,
    );
}
unsafe extern "C" fn local_do_shell(mut args: *const libc::c_char) {
    let mut status: libc::c_int = 0;
    let mut shell: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pid: pid_t = 0;
    if *args == 0 {
        args = 0 as *const libc::c_char;
    }
    shell = getenv(b"SHELL\0" as *const u8 as *const libc::c_char);
    if shell.is_null() || *shell as libc::c_int == '\0' as i32 {
        shell = b"/bin/sh\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    pid = libc::fork();
    if pid == -(1 as libc::c_int) {
        sshfatal(
            b"sftp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"local_do_shell\0"))
                .as_ptr(),
            335 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Couldn't libc::fork: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    if pid == 0 as libc::c_int {
        if !args.is_null() {
            crate::log::sshlog(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"local_do_shell\0"))
                    .as_ptr(),
                340 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"Executing %s -c \"%s\"\0" as *const u8 as *const libc::c_char,
                shell,
                args,
            );
            execl(
                shell,
                shell,
                b"-c\0" as *const u8 as *const libc::c_char,
                args,
                0 as *mut libc::c_void as *mut libc::c_char,
            );
        } else {
            crate::log::sshlog(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"local_do_shell\0"))
                    .as_ptr(),
                343 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"Executing %s\0" as *const u8 as *const libc::c_char,
                shell,
            );
            execl(shell, shell, 0 as *mut libc::c_void as *mut libc::c_char);
        }
        libc::fprintf(
            stderr,
            b"Couldn't execute \"%s\": %s\n\0" as *const u8 as *const libc::c_char,
            shell,
            strerror(*libc::__errno_location()),
        );
        libc::_exit(1 as libc::c_int);
    }
    while libc::waitpid(pid, &mut status, 0 as libc::c_int) == -(1 as libc::c_int) {
        if *libc::__errno_location() != 4 as libc::c_int {
            sshfatal(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"local_do_shell\0"))
                    .as_ptr(),
                352 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Couldn't wait for child: %s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
    }
    if !(status & 0x7f as libc::c_int == 0 as libc::c_int) {
        crate::log::sshlog(
            b"sftp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"local_do_shell\0"))
                .as_ptr(),
            354 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Shell exited abnormally\0" as *const u8 as *const libc::c_char,
        );
    } else if (status & 0xff00 as libc::c_int) >> 8 as libc::c_int != 0 {
        crate::log::sshlog(
            b"sftp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"local_do_shell\0"))
                .as_ptr(),
            356 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Shell exited with status %d\0" as *const u8 as *const libc::c_char,
            (status & 0xff00 as libc::c_int) >> 8 as libc::c_int,
        );
    }
}
unsafe extern "C" fn local_do_ls(mut args: *const libc::c_char) {
    if args.is_null() || *args == 0 {
        local_do_shell(b"ls\0" as *const u8 as *const libc::c_char);
    } else {
        let mut len: libc::c_int = (strlen(b"ls \0" as *const u8 as *const libc::c_char))
            .wrapping_add(strlen(args))
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            as libc::c_int;
        let mut buf: *mut libc::c_char = xmalloc(len as size_t) as *mut libc::c_char;
        libc::snprintf(
            buf,
            len as usize,
            b"ls %s\0" as *const u8 as *const libc::c_char,
            args,
        );
        local_do_shell(buf);
        libc::free(buf as *mut libc::c_void);
    };
}
unsafe extern "C" fn path_strip(
    mut path: *const libc::c_char,
    mut strip: *const libc::c_char,
) -> *mut libc::c_char {
    let mut len: size_t = 0;
    if strip.is_null() {
        return xstrdup(path);
    }
    len = strlen(strip);
    if strncmp(path, strip, len) == 0 as libc::c_int {
        if *strip.offset(len.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize)
            as libc::c_int
            != '/' as i32
            && *path.offset(len as isize) as libc::c_int == '/' as i32
        {
            len = len.wrapping_add(1);
            len;
        }
        return xstrdup(path.offset(len as isize));
    }
    return xstrdup(path);
}
unsafe extern "C" fn parse_getput_flags(
    mut cmd: *const libc::c_char,
    mut argv: *mut *mut libc::c_char,
    mut argc: libc::c_int,
    mut aflag: *mut libc::c_int,
    mut fflag: *mut libc::c_int,
    mut pflag: *mut libc::c_int,
    mut rflag: *mut libc::c_int,
) -> libc::c_int {
    extern "C" {
        #[link_name = "BSDopterr"]
        static mut BSDopterr_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptopt"]
        static mut BSDoptopt_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptreset"]
        static mut BSDoptreset_0: libc::c_int;
    }
    let mut ch: libc::c_int = 0;
    BSDoptreset = 1 as libc::c_int;
    BSDoptind = BSDoptreset;
    BSDopterr = 0 as libc::c_int;
    *pflag = 0 as libc::c_int;
    *rflag = *pflag;
    *fflag = *rflag;
    *aflag = *fflag;
    loop {
        ch = BSDgetopt(argc, argv, b"afPpRr\0" as *const u8 as *const libc::c_char);
        if !(ch != -(1 as libc::c_int)) {
            break;
        }
        match ch {
            97 => {
                *aflag = 1 as libc::c_int;
            }
            102 => {
                *fflag = 1 as libc::c_int;
            }
            112 | 80 => {
                *pflag = 1 as libc::c_int;
            }
            114 | 82 => {
                *rflag = 1 as libc::c_int;
            }
            _ => {
                crate::log::sshlog(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"parse_getput_flags\0",
                    ))
                    .as_ptr(),
                    422 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s: Invalid flag -%c\0" as *const u8 as *const libc::c_char,
                    cmd,
                    BSDoptopt,
                );
                return -(1 as libc::c_int);
            }
        }
    }
    return BSDoptind;
}
unsafe extern "C" fn parse_link_flags(
    mut cmd: *const libc::c_char,
    mut argv: *mut *mut libc::c_char,
    mut argc: libc::c_int,
    mut sflag: *mut libc::c_int,
) -> libc::c_int {
    extern "C" {
        #[link_name = "BSDopterr"]
        static mut BSDopterr_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptopt"]
        static mut BSDoptopt_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptreset"]
        static mut BSDoptreset_0: libc::c_int;
    }
    let mut ch: libc::c_int = 0;
    BSDoptreset = 1 as libc::c_int;
    BSDoptind = BSDoptreset;
    BSDopterr = 0 as libc::c_int;
    *sflag = 0 as libc::c_int;
    loop {
        ch = BSDgetopt(argc, argv, b"s\0" as *const u8 as *const libc::c_char);
        if !(ch != -(1 as libc::c_int)) {
            break;
        }
        match ch {
            115 => {
                *sflag = 1 as libc::c_int;
            }
            _ => {
                crate::log::sshlog(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                        b"parse_link_flags\0",
                    ))
                    .as_ptr(),
                    446 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s: Invalid flag -%c\0" as *const u8 as *const libc::c_char,
                    cmd,
                    BSDoptopt,
                );
                return -(1 as libc::c_int);
            }
        }
    }
    return BSDoptind;
}
unsafe extern "C" fn parse_rename_flags(
    mut cmd: *const libc::c_char,
    mut argv: *mut *mut libc::c_char,
    mut argc: libc::c_int,
    mut lflag: *mut libc::c_int,
) -> libc::c_int {
    extern "C" {
        #[link_name = "BSDopterr"]
        static mut BSDopterr_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptopt"]
        static mut BSDoptopt_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptreset"]
        static mut BSDoptreset_0: libc::c_int;
    }
    let mut ch: libc::c_int = 0;
    BSDoptreset = 1 as libc::c_int;
    BSDoptind = BSDoptreset;
    BSDopterr = 0 as libc::c_int;
    *lflag = 0 as libc::c_int;
    loop {
        ch = BSDgetopt(argc, argv, b"l\0" as *const u8 as *const libc::c_char);
        if !(ch != -(1 as libc::c_int)) {
            break;
        }
        match ch {
            108 => {
                *lflag = 1 as libc::c_int;
            }
            _ => {
                crate::log::sshlog(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"parse_rename_flags\0",
                    ))
                    .as_ptr(),
                    470 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s: Invalid flag -%c\0" as *const u8 as *const libc::c_char,
                    cmd,
                    BSDoptopt,
                );
                return -(1 as libc::c_int);
            }
        }
    }
    return BSDoptind;
}
unsafe extern "C" fn parse_ls_flags(
    mut argv: *mut *mut libc::c_char,
    mut argc: libc::c_int,
    mut lflag: *mut libc::c_int,
) -> libc::c_int {
    extern "C" {
        #[link_name = "BSDopterr"]
        static mut BSDopterr_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptopt"]
        static mut BSDoptopt_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptreset"]
        static mut BSDoptreset_0: libc::c_int;
    }
    let mut ch: libc::c_int = 0;
    BSDoptreset = 1 as libc::c_int;
    BSDoptind = BSDoptreset;
    BSDopterr = 0 as libc::c_int;
    *lflag = 0x8 as libc::c_int;
    loop {
        ch = BSDgetopt(
            argc,
            argv,
            b"1Safhlnrt\0" as *const u8 as *const libc::c_char,
        );
        if !(ch != -(1 as libc::c_int)) {
            break;
        }
        match ch {
            49 => {
                *lflag &= !(0x1 as libc::c_int
                    | 0x2 as libc::c_int
                    | 0x4 as libc::c_int
                    | 0x100 as libc::c_int);
                *lflag |= 0x2 as libc::c_int;
            }
            83 => {
                *lflag &= !(0x8 as libc::c_int | 0x10 as libc::c_int | 0x20 as libc::c_int);
                *lflag |= 0x20 as libc::c_int;
            }
            97 => {
                *lflag |= 0x80 as libc::c_int;
            }
            102 => {
                *lflag &= !(0x8 as libc::c_int | 0x10 as libc::c_int | 0x20 as libc::c_int);
            }
            104 => {
                *lflag |= 0x100 as libc::c_int;
            }
            108 => {
                *lflag &= !(0x2 as libc::c_int);
                *lflag |= 0x1 as libc::c_int;
            }
            110 => {
                *lflag &= !(0x2 as libc::c_int);
                *lflag |= 0x4 as libc::c_int | 0x1 as libc::c_int;
            }
            114 => {
                *lflag |= 0x40 as libc::c_int;
            }
            116 => {
                *lflag &= !(0x8 as libc::c_int | 0x10 as libc::c_int | 0x20 as libc::c_int);
                *lflag |= 0x10 as libc::c_int;
            }
            _ => {
                crate::log::sshlog(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"parse_ls_flags\0",
                    ))
                    .as_ptr(),
                    523 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"ls: Invalid flag -%c\0" as *const u8 as *const libc::c_char,
                    BSDoptopt,
                );
                return -(1 as libc::c_int);
            }
        }
    }
    return BSDoptind;
}
unsafe extern "C" fn parse_df_flags(
    mut cmd: *const libc::c_char,
    mut argv: *mut *mut libc::c_char,
    mut argc: libc::c_int,
    mut hflag: *mut libc::c_int,
    mut iflag: *mut libc::c_int,
) -> libc::c_int {
    extern "C" {
        #[link_name = "BSDopterr"]
        static mut BSDopterr_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptopt"]
        static mut BSDoptopt_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptreset"]
        static mut BSDoptreset_0: libc::c_int;
    }
    let mut ch: libc::c_int = 0;
    BSDoptreset = 1 as libc::c_int;
    BSDoptind = BSDoptreset;
    BSDopterr = 0 as libc::c_int;
    *iflag = 0 as libc::c_int;
    *hflag = *iflag;
    loop {
        ch = BSDgetopt(argc, argv, b"hi\0" as *const u8 as *const libc::c_char);
        if !(ch != -(1 as libc::c_int)) {
            break;
        }
        match ch {
            104 => {
                *hflag = 1 as libc::c_int;
            }
            105 => {
                *iflag = 1 as libc::c_int;
            }
            _ => {
                crate::log::sshlog(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"parse_df_flags\0",
                    ))
                    .as_ptr(),
                    550 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s: Invalid flag -%c\0" as *const u8 as *const libc::c_char,
                    cmd,
                    BSDoptopt,
                );
                return -(1 as libc::c_int);
            }
        }
    }
    return BSDoptind;
}
unsafe extern "C" fn parse_ch_flags(
    mut cmd: *const libc::c_char,
    mut argv: *mut *mut libc::c_char,
    mut argc: libc::c_int,
    mut hflag: *mut libc::c_int,
) -> libc::c_int {
    extern "C" {
        #[link_name = "BSDopterr"]
        static mut BSDopterr_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptopt"]
        static mut BSDoptopt_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptreset"]
        static mut BSDoptreset_0: libc::c_int;
    }
    let mut ch: libc::c_int = 0;
    BSDoptreset = 1 as libc::c_int;
    BSDoptind = BSDoptreset;
    BSDopterr = 0 as libc::c_int;
    *hflag = 0 as libc::c_int;
    loop {
        ch = BSDgetopt(argc, argv, b"h\0" as *const u8 as *const libc::c_char);
        if !(ch != -(1 as libc::c_int)) {
            break;
        }
        match ch {
            104 => {
                *hflag = 1 as libc::c_int;
            }
            _ => {
                crate::log::sshlog(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"parse_ch_flags\0",
                    ))
                    .as_ptr(),
                    574 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s: Invalid flag -%c\0" as *const u8 as *const libc::c_char,
                    cmd,
                    BSDoptopt,
                );
                return -(1 as libc::c_int);
            }
        }
    }
    return BSDoptind;
}
unsafe extern "C" fn parse_no_flags(
    mut cmd: *const libc::c_char,
    mut argv: *mut *mut libc::c_char,
    mut argc: libc::c_int,
) -> libc::c_int {
    extern "C" {
        #[link_name = "BSDopterr"]
        static mut BSDopterr_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptopt"]
        static mut BSDoptopt_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptreset"]
        static mut BSDoptreset_0: libc::c_int;
    }
    let mut ch: libc::c_int = 0;
    BSDoptreset = 1 as libc::c_int;
    BSDoptind = BSDoptreset;
    BSDopterr = 0 as libc::c_int;
    ch = BSDgetopt(argc, argv, b"\0" as *const u8 as *const libc::c_char);
    if ch != -(1 as libc::c_int) {
        match ch {
            _ => {}
        }
        crate::log::sshlog(
            b"sftp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"parse_no_flags\0"))
                .as_ptr(),
            594 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s: Invalid flag -%c\0" as *const u8 as *const libc::c_char,
            cmd,
            BSDoptopt,
        );
        return -(1 as libc::c_int);
    }
    return BSDoptind;
}
unsafe extern "C" fn escape_glob(mut s: *const libc::c_char) -> *mut libc::c_char {
    let mut i: size_t = 0;
    let mut o: size_t = 0;
    let mut len: size_t = 0;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    len = strlen(s);
    ret = xcalloc(
        2 as libc::c_int as size_t,
        len.wrapping_add(1 as libc::c_int as libc::c_ulong),
    ) as *mut libc::c_char;
    o = 0 as libc::c_int as size_t;
    i = o;
    while i < len {
        if !(strchr(
            b"[]?*\\\0" as *const u8 as *const libc::c_char,
            *s.offset(i as isize) as libc::c_int,
        ))
        .is_null()
        {
            let fresh0 = o;
            o = o.wrapping_add(1);
            *ret.offset(fresh0 as isize) = '\\' as i32 as libc::c_char;
        }
        let fresh1 = o;
        o = o.wrapping_add(1);
        *ret.offset(fresh1 as isize) = *s.offset(i as isize);
        i = i.wrapping_add(1);
        i;
    }
    let fresh2 = o;
    o = o.wrapping_add(1);
    *ret.offset(fresh2 as isize) = '\0' as i32 as libc::c_char;
    return ret;
}
unsafe extern "C" fn make_absolute_pwd_glob(
    mut p: *mut libc::c_char,
    mut pwd: *const libc::c_char,
) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut escpwd: *mut libc::c_char = 0 as *mut libc::c_char;
    escpwd = escape_glob(pwd);
    if p.is_null() {
        return escpwd;
    }
    ret = make_absolute(p, escpwd);
    libc::free(escpwd as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn process_get(
    mut conn: *mut sftp_conn,
    mut src: *const libc::c_char,
    mut dst: *const libc::c_char,
    mut pwd: *const libc::c_char,
    mut pflag: libc::c_int,
    mut rflag: libc::c_int,
    mut resume: libc::c_int,
    mut fflag: libc::c_int,
) -> libc::c_int {
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut abs_src: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut abs_dst: *mut libc::c_char = 0 as *mut libc::c_char;
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
    let mut err: libc::c_int = 0 as libc::c_int;
    abs_src = make_absolute_pwd_glob(xstrdup(src), pwd);
    memset(
        &mut g as *mut _ssh_compat_glob_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<_ssh_compat_glob_t>() as libc::c_ulong,
    );
    crate::log::sshlog(
        b"sftp.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_get\0")).as_ptr(),
        647 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Looking up %s\0" as *const u8 as *const libc::c_char,
        abs_src,
    );
    r = remote_glob(conn, abs_src, 0x8 as libc::c_int, None, &mut g);
    if r != 0 as libc::c_int {
        if r == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_get\0"))
                    .as_ptr(),
                650 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Too many matches for \"%s\".\0" as *const u8 as *const libc::c_char,
                abs_src,
            );
        } else {
            crate::log::sshlog(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_get\0"))
                    .as_ptr(),
                652 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"File \"%s\" not found.\0" as *const u8 as *const libc::c_char,
                abs_src,
            );
        }
        err = -(1 as libc::c_int);
    } else if g.gl_matchc > 1 as libc::c_int as libc::c_ulong
        && !dst.is_null()
        && local_is_dir(dst) == 0
    {
        crate::log::sshlog(
            b"sftp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_get\0")).as_ptr(),
            664 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Multiple source paths, but destination \"%s\" is not a directory\0" as *const u8
                as *const libc::c_char,
            dst,
        );
        err = -(1 as libc::c_int);
    } else {
        i = 0 as libc::c_int;
        while !(*(g.gl_pathv).offset(i as isize)).is_null() && interrupted == 0 {
            tmp = xstrdup(*(g.gl_pathv).offset(i as isize));
            filename = __xpg_basename(tmp);
            if filename.is_null() {
                crate::log::sshlog(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_get\0"))
                        .as_ptr(),
                    672 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"basename %s: %s\0" as *const u8 as *const libc::c_char,
                    tmp,
                    strerror(*libc::__errno_location()),
                );
                libc::free(tmp as *mut libc::c_void);
                err = -(1 as libc::c_int);
                break;
            } else {
                if g.gl_matchc == 1 as libc::c_int as libc::c_ulong && !dst.is_null() {
                    if local_is_dir(dst) != 0 {
                        abs_dst = path_append(dst, filename);
                    } else {
                        abs_dst = xstrdup(dst);
                    }
                } else if !dst.is_null() {
                    abs_dst = path_append(dst, filename);
                } else {
                    abs_dst = xstrdup(filename);
                }
                libc::free(tmp as *mut libc::c_void);
                resume |= global_aflag;
                if quiet == 0 && resume != 0 {
                    mprintf(
                        b"Resuming %s to %s\n\0" as *const u8 as *const libc::c_char,
                        *(g.gl_pathv).offset(i as isize),
                        abs_dst,
                    );
                } else if quiet == 0 && resume == 0 {
                    mprintf(
                        b"Fetching %s to %s\n\0" as *const u8 as *const libc::c_char,
                        *(g.gl_pathv).offset(i as isize),
                        abs_dst,
                    );
                }
                if globpath_is_dir(*(g.gl_pathv).offset(i as isize)) != 0
                    && (rflag != 0 || global_rflag != 0)
                {
                    if download_dir(
                        conn,
                        *(g.gl_pathv).offset(i as isize),
                        abs_dst,
                        0 as *mut Attrib,
                        (pflag != 0 || global_pflag != 0) as libc::c_int,
                        1 as libc::c_int,
                        resume,
                        (fflag != 0 || global_fflag != 0) as libc::c_int,
                        0 as libc::c_int,
                        0 as libc::c_int,
                    ) == -(1 as libc::c_int)
                    {
                        err = -(1 as libc::c_int);
                    }
                } else if crate::sftp_client::do_download(
                    conn,
                    *(g.gl_pathv).offset(i as isize),
                    abs_dst,
                    0 as *mut Attrib,
                    (pflag != 0 || global_pflag != 0) as libc::c_int,
                    resume,
                    (fflag != 0 || global_fflag != 0) as libc::c_int,
                    0 as libc::c_int,
                ) == -(1 as libc::c_int)
                {
                    err = -(1 as libc::c_int);
                }
                libc::free(abs_dst as *mut libc::c_void);
                abs_dst = 0 as *mut libc::c_char;
                i += 1;
                i;
            }
        }
    }
    libc::free(abs_src as *mut libc::c_void);
    _ssh__compat_globfree(&mut g);
    return err;
}
unsafe extern "C" fn process_put(
    mut conn: *mut sftp_conn,
    mut src: *const libc::c_char,
    mut dst: *const libc::c_char,
    mut pwd: *const libc::c_char,
    mut pflag: libc::c_int,
    mut rflag: libc::c_int,
    mut resume: libc::c_int,
    mut fflag: libc::c_int,
) -> libc::c_int {
    let mut tmp_dst: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut abs_dst: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut filename: *mut libc::c_char = 0 as *mut libc::c_char;
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
    let mut err: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut dst_is_dir: libc::c_int = 1 as libc::c_int;
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    if !dst.is_null() {
        tmp_dst = xstrdup(dst);
        tmp_dst = make_absolute(tmp_dst, pwd);
    }
    memset(
        &mut g as *mut _ssh_compat_glob_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<_ssh_compat_glob_t>() as libc::c_ulong,
    );
    crate::log::sshlog(
        b"sftp.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_put\0")).as_ptr(),
        738 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"Looking up %s\0" as *const u8 as *const libc::c_char,
        src,
    );
    if _ssh__compat_glob(src, 0x10 as libc::c_int | 0x8 as libc::c_int, None, &mut g) != 0 {
        crate::log::sshlog(
            b"sftp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_put\0")).as_ptr(),
            740 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"File \"%s\" not found.\0" as *const u8 as *const libc::c_char,
            src,
        );
        err = -(1 as libc::c_int);
    } else {
        if !tmp_dst.is_null() {
            dst_is_dir = remote_is_dir(conn, tmp_dst);
        }
        if g.gl_matchc > 1 as libc::c_int as libc::c_ulong && !tmp_dst.is_null() && dst_is_dir == 0
        {
            crate::log::sshlog(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"process_put\0"))
                    .as_ptr(),
                752 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Multiple paths match, but destination \"%s\" is not a directory\0" as *const u8
                    as *const libc::c_char,
                tmp_dst,
            );
            err = -(1 as libc::c_int);
        } else {
            i = 0 as libc::c_int;
            while !(*(g.gl_pathv).offset(i as isize)).is_null() && interrupted == 0 {
                if libc::stat(*(g.gl_pathv).offset(i as isize), &mut sb) == -(1 as libc::c_int) {
                    err = -(1 as libc::c_int);
                    crate::log::sshlog(
                        b"sftp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                            b"process_put\0",
                        ))
                        .as_ptr(),
                        760 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"libc::stat %s: %s\0" as *const u8 as *const libc::c_char,
                        *(g.gl_pathv).offset(i as isize),
                        strerror(*libc::__errno_location()),
                    );
                } else {
                    tmp = xstrdup(*(g.gl_pathv).offset(i as isize));
                    filename = __xpg_basename(tmp);
                    if filename.is_null() {
                        crate::log::sshlog(
                            b"sftp.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(
                                b"process_put\0",
                            ))
                            .as_ptr(),
                            766 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"basename %s: %s\0" as *const u8 as *const libc::c_char,
                            tmp,
                            strerror(*libc::__errno_location()),
                        );
                        libc::free(tmp as *mut libc::c_void);
                        err = -(1 as libc::c_int);
                        break;
                    } else {
                        libc::free(abs_dst as *mut libc::c_void);
                        abs_dst = 0 as *mut libc::c_char;
                        if g.gl_matchc == 1 as libc::c_int as libc::c_ulong && !tmp_dst.is_null() {
                            if dst_is_dir != 0 {
                                abs_dst = path_append(tmp_dst, filename);
                            } else {
                                abs_dst = xstrdup(tmp_dst);
                            }
                        } else if !tmp_dst.is_null() {
                            abs_dst = path_append(tmp_dst, filename);
                        } else {
                            abs_dst = make_absolute(xstrdup(filename), pwd);
                        }
                        libc::free(tmp as *mut libc::c_void);
                        resume |= global_aflag;
                        if quiet == 0 && resume != 0 {
                            mprintf(
                                b"Resuming upload of %s to %s\n\0" as *const u8
                                    as *const libc::c_char,
                                *(g.gl_pathv).offset(i as isize),
                                abs_dst,
                            );
                        } else if quiet == 0 && resume == 0 {
                            mprintf(
                                b"Uploading %s to %s\n\0" as *const u8 as *const libc::c_char,
                                *(g.gl_pathv).offset(i as isize),
                                abs_dst,
                            );
                        }
                        if globpath_is_dir(*(g.gl_pathv).offset(i as isize)) != 0
                            && (rflag != 0 || global_rflag != 0)
                        {
                            if upload_dir(
                                conn,
                                *(g.gl_pathv).offset(i as isize),
                                abs_dst,
                                (pflag != 0 || global_pflag != 0) as libc::c_int,
                                1 as libc::c_int,
                                resume,
                                (fflag != 0 || global_fflag != 0) as libc::c_int,
                                0 as libc::c_int,
                                0 as libc::c_int,
                            ) == -(1 as libc::c_int)
                            {
                                err = -(1 as libc::c_int);
                            }
                        } else if do_upload(
                            conn,
                            *(g.gl_pathv).offset(i as isize),
                            abs_dst,
                            (pflag != 0 || global_pflag != 0) as libc::c_int,
                            resume,
                            (fflag != 0 || global_fflag != 0) as libc::c_int,
                            0 as libc::c_int,
                        ) == -(1 as libc::c_int)
                        {
                            err = -(1 as libc::c_int);
                        }
                    }
                }
                i += 1;
                i;
            }
        }
    }
    libc::free(abs_dst as *mut libc::c_void);
    libc::free(tmp_dst as *mut libc::c_void);
    _ssh__compat_globfree(&mut g);
    return err;
}
unsafe extern "C" fn sdirent_comp(
    mut aa: *const libc::c_void,
    mut bb: *const libc::c_void,
) -> libc::c_int {
    let mut a: *mut SFTP_DIRENT = *(aa as *mut *mut SFTP_DIRENT);
    let mut b: *mut SFTP_DIRENT = *(bb as *mut *mut SFTP_DIRENT);
    let mut rmul: libc::c_int = if sort_flag & 0x40 as libc::c_int != 0 {
        -(1 as libc::c_int)
    } else {
        1 as libc::c_int
    };
    if sort_flag & 0x8 as libc::c_int != 0 {
        return rmul * strcmp((*a).filename, (*b).filename);
    } else if sort_flag & 0x10 as libc::c_int != 0 {
        return rmul
            * (if (*a).a.mtime == (*b).a.mtime {
                0 as libc::c_int
            } else {
                if (*a).a.mtime < (*b).a.mtime {
                    1 as libc::c_int
                } else {
                    -(1 as libc::c_int)
                }
            });
    } else if sort_flag & 0x20 as libc::c_int != 0 {
        return rmul
            * (if (*a).a.size == (*b).a.size {
                0 as libc::c_int
            } else {
                if (*a).a.size < (*b).a.size {
                    1 as libc::c_int
                } else {
                    -(1 as libc::c_int)
                }
            });
    }
    sshfatal(
        b"sftp.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sdirent_comp\0")).as_ptr(),
        830 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_FATAL,
        0 as *const libc::c_char,
        b"Unknown ls sort type\0" as *const u8 as *const libc::c_char,
    );
}
unsafe extern "C" fn do_ls_dir(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
    mut strip_path: *const libc::c_char,
    mut lflag: libc::c_int,
) -> libc::c_int {
    let mut n: libc::c_int = 0;
    let mut c: u_int = 1 as libc::c_int as u_int;
    let mut colspace: u_int = 0 as libc::c_int as u_int;
    let mut columns: u_int = 1 as libc::c_int as u_int;
    let mut d: *mut *mut SFTP_DIRENT = 0 as *mut *mut SFTP_DIRENT;
    n = do_readdir(conn, path, &mut d);
    if n != 0 as libc::c_int {
        return n;
    }
    if lflag & 0x2 as libc::c_int == 0 {
        let mut m: u_int = 0 as libc::c_int as u_int;
        let mut width: u_int = 80 as libc::c_int as u_int;
        let mut ws: winsize = winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
        n = 0 as libc::c_int;
        while !(*d.offset(n as isize)).is_null() {
            if *((**d.offset(n as isize)).filename).offset(0 as libc::c_int as isize) as libc::c_int
                != '.' as i32
                || lflag & 0x80 as libc::c_int != 0
            {
                m = (if m as libc::c_ulong > strlen((**d.offset(n as isize)).filename) {
                    m as libc::c_ulong
                } else {
                    strlen((**d.offset(n as isize)).filename)
                }) as u_int;
            }
            n += 1;
            n;
        }
        tmp = path_strip(path, strip_path);
        m = (m as libc::c_ulong).wrapping_add(strlen(tmp)) as u_int as u_int;
        libc::free(tmp as *mut libc::c_void);
        if ioctl(
            fileno(stdin),
            0x5413 as libc::c_int as libc::c_ulong,
            &mut ws as *mut winsize,
        ) != -(1 as libc::c_int)
        {
            width = ws.ws_col as u_int;
        }
        columns = width.wrapping_div(m.wrapping_add(2 as libc::c_int as libc::c_uint));
        columns = if columns > 1 as libc::c_int as libc::c_uint {
            columns
        } else {
            1 as libc::c_int as libc::c_uint
        };
        colspace = width.wrapping_div(columns);
        colspace = if colspace < width { colspace } else { width };
    }
    if lflag & (0x8 as libc::c_int | 0x10 as libc::c_int | 0x20 as libc::c_int) != 0 {
        n = 0 as libc::c_int;
        while !(*d.offset(n as isize)).is_null() {
            n += 1;
            n;
        }
        sort_flag = lflag
            & (0x8 as libc::c_int
                | 0x10 as libc::c_int
                | 0x20 as libc::c_int
                | 0x40 as libc::c_int);
        qsort(
            d as *mut libc::c_void,
            n as size_t,
            ::core::mem::size_of::<*mut SFTP_DIRENT>() as libc::c_ulong,
            Some(
                sdirent_comp
                    as unsafe extern "C" fn(
                        *const libc::c_void,
                        *const libc::c_void,
                    ) -> libc::c_int,
            ),
        );
    }
    get_remote_user_groups_from_dirents(conn, d);
    n = 0 as libc::c_int;
    while !(*d.offset(n as isize)).is_null() && interrupted == 0 {
        let mut tmp_0: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut fname: *mut libc::c_char = 0 as *mut libc::c_char;
        if !(*((**d.offset(n as isize)).filename).offset(0 as libc::c_int as isize) as libc::c_int
            == '.' as i32
            && lflag & 0x80 as libc::c_int == 0)
        {
            tmp_0 = path_append(path, (**d.offset(n as isize)).filename);
            fname = path_strip(tmp_0, strip_path);
            libc::free(tmp_0 as *mut libc::c_void);
            if lflag & 0x1 as libc::c_int != 0 {
                if lflag & (0x4 as libc::c_int | 0x100 as libc::c_int) != 0 as libc::c_int
                    || can_get_users_groups_by_id(conn) != 0
                {
                    let mut lname: *mut libc::c_char = 0 as *mut libc::c_char;
                    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
                    memset(
                        &mut sb as *mut libc::stat as *mut libc::c_void,
                        0 as libc::c_int,
                        ::core::mem::size_of::<libc::stat>() as libc::c_ulong,
                    );
                    attrib_to_stat(&mut (**d.offset(n as isize)).a, &mut sb);
                    lname = ls_file(
                        fname,
                        &mut sb,
                        1 as libc::c_int,
                        lflag & 0x100 as libc::c_int,
                        ruser_name(sb.st_uid),
                        rgroup_name(sb.st_gid),
                    );
                    mprintf(b"%s\n\0" as *const u8 as *const libc::c_char, lname);
                    libc::free(lname as *mut libc::c_void);
                } else {
                    mprintf(
                        b"%s\n\0" as *const u8 as *const libc::c_char,
                        (**d.offset(n as isize)).longname,
                    );
                }
            } else {
                mprintf(
                    b"%-*s\0" as *const u8 as *const libc::c_char,
                    colspace,
                    fname,
                );
                if c >= columns {
                    printf(b"\n\0" as *const u8 as *const libc::c_char);
                    c = 1 as libc::c_int as u_int;
                } else {
                    c = c.wrapping_add(1);
                    c;
                }
            }
            libc::free(fname as *mut libc::c_void);
        }
        n += 1;
        n;
    }
    if lflag & 0x1 as libc::c_int == 0 && c != 1 as libc::c_int as libc::c_uint {
        printf(b"\n\0" as *const u8 as *const libc::c_char);
    }
    free_sftp_dirents(d);
    return 0 as libc::c_int;
}
unsafe extern "C" fn sglob_comp(
    mut aa: *const libc::c_void,
    mut bb: *const libc::c_void,
) -> libc::c_int {
    let mut a: u_int = *(aa as *const u_int);
    let mut b: u_int = *(bb as *const u_int);
    let mut ap: *const libc::c_char = *((*sort_glob).gl_pathv).offset(a as isize);
    let mut bp: *const libc::c_char = *((*sort_glob).gl_pathv).offset(b as isize);
    let mut as_0: *const libc::stat = *((*sort_glob).gl_statv).offset(a as isize);
    let mut bs: *const libc::stat = *((*sort_glob).gl_statv).offset(b as isize);
    let mut rmul: libc::c_int = if sort_flag & 0x40 as libc::c_int != 0 {
        -(1 as libc::c_int)
    } else {
        1 as libc::c_int
    };
    if sort_flag & 0x8 as libc::c_int != 0 {
        return rmul * strcmp(ap, bp);
    } else if sort_flag & 0x10 as libc::c_int != 0 {
        if if (*as_0).st_mtime == (*bs).st_mtime {
            ((*as_0).st_mtime_nsec == (*bs).st_mtime_nsec) as libc::c_int
        } else {
            ((*as_0).st_mtime == (*bs).st_mtime) as libc::c_int
        } != 0
        {
            return 0 as libc::c_int;
        }
        return if if (*as_0).st_mtime == (*bs).st_mtime {
            ((*as_0).st_mtime_nsec < (*bs).st_mtime_nsec) as libc::c_int
        } else {
            ((*as_0).st_mtime < (*bs).st_mtime) as libc::c_int
        } != 0
        {
            rmul
        } else {
            -rmul
        };
    } else if sort_flag & 0x20 as libc::c_int != 0 {
        return rmul
            * (if (*as_0).st_size == (*bs).st_size {
                0 as libc::c_int
            } else {
                if (*as_0).st_size < (*bs).st_size {
                    1 as libc::c_int
                } else {
                    -(1 as libc::c_int)
                }
            });
    }
    sshfatal(
        b"sftp.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sglob_comp\0")).as_ptr(),
        951 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_FATAL,
        0 as *const libc::c_char,
        b"Unknown ls sort type\0" as *const u8 as *const libc::c_char,
    );
}
unsafe extern "C" fn do_globbed_ls(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
    mut strip_path: *const libc::c_char,
    mut lflag: libc::c_int,
) -> libc::c_int {
    let mut fname: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut lname: *mut libc::c_char = 0 as *mut libc::c_char;
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
    let mut err: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut ws: winsize = winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let mut i: u_int = 0;
    let mut j: u_int = 0;
    let mut nentries: u_int = 0;
    let mut indices: *mut u_int = 0 as *mut u_int;
    let mut c: u_int = 1 as libc::c_int as u_int;
    let mut colspace: u_int = 0 as libc::c_int as u_int;
    let mut columns: u_int = 1 as libc::c_int as u_int;
    let mut m: u_int = 0 as libc::c_int as u_int;
    let mut width: u_int = 80 as libc::c_int as u_int;
    memset(
        &mut g as *mut _ssh_compat_glob_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<_ssh_compat_glob_t>() as libc::c_ulong,
    );
    r = remote_glob(
        conn,
        path,
        0x8 as libc::c_int
            | 0x10 as libc::c_int
            | 0x80 as libc::c_int
            | 0x4000 as libc::c_int
            | 0x20 as libc::c_int,
        None,
        &mut g,
    );
    if r != 0 as libc::c_int || g.gl_pathc != 0 && g.gl_matchc == 0 {
        if g.gl_pathc != 0 {
            _ssh__compat_globfree(&mut g);
        }
        if r == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"do_globbed_ls\0"))
                    .as_ptr(),
                975 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Can't ls: Too many matches for \"%s\"\0" as *const u8 as *const libc::c_char,
                path,
            );
        } else {
            crate::log::sshlog(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"do_globbed_ls\0"))
                    .as_ptr(),
                977 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Can't ls: \"%s\" not found\0" as *const u8 as *const libc::c_char,
                path,
            );
        }
        return -(1 as libc::c_int);
    }
    if !(interrupted != 0) {
        if g.gl_matchc == 1 as libc::c_int as libc::c_ulong
            && !(*(g.gl_statv).offset(0 as libc::c_int as isize)).is_null()
            && (**(g.gl_statv).offset(0 as libc::c_int as isize)).st_mode
                & 0o170000 as libc::c_int as libc::c_uint
                == 0o40000 as libc::c_int as libc::c_uint
        {
            err = do_ls_dir(
                conn,
                *(g.gl_pathv).offset(0 as libc::c_int as isize),
                strip_path,
                lflag,
            );
            _ssh__compat_globfree(&mut g);
            return err;
        }
        if ioctl(
            fileno(stdin),
            0x5413 as libc::c_int as libc::c_ulong,
            &mut ws as *mut winsize,
        ) != -(1 as libc::c_int)
        {
            width = ws.ws_col as u_int;
        }
        if lflag & 0x2 as libc::c_int == 0 {
            i = 0 as libc::c_int as u_int;
            while !(*(g.gl_pathv).offset(i as isize)).is_null() {
                m = (if m as libc::c_ulong > strlen(*(g.gl_pathv).offset(i as isize)) {
                    m as libc::c_ulong
                } else {
                    strlen(*(g.gl_pathv).offset(i as isize))
                }) as u_int;
                i = i.wrapping_add(1);
                i;
            }
            columns = width.wrapping_div(m.wrapping_add(2 as libc::c_int as libc::c_uint));
            columns = if columns > 1 as libc::c_int as libc::c_uint {
                columns
            } else {
                1 as libc::c_int as libc::c_uint
            };
            colspace = width.wrapping_div(columns);
        }
        nentries = 0 as libc::c_int as u_int;
        while !(*(g.gl_pathv).offset(nentries as isize)).is_null() {
            nentries = nentries.wrapping_add(1);
            nentries;
        }
        indices = xcalloc(
            nentries as size_t,
            ::core::mem::size_of::<u_int>() as libc::c_ulong,
        ) as *mut u_int;
        i = 0 as libc::c_int as u_int;
        while i < nentries {
            *indices.offset(i as isize) = i;
            i = i.wrapping_add(1);
            i;
        }
        if lflag & (0x8 as libc::c_int | 0x10 as libc::c_int | 0x20 as libc::c_int) != 0 {
            sort_glob = &mut g;
            sort_flag = lflag
                & (0x8 as libc::c_int
                    | 0x10 as libc::c_int
                    | 0x20 as libc::c_int
                    | 0x40 as libc::c_int);
            qsort(
                indices as *mut libc::c_void,
                nentries as size_t,
                ::core::mem::size_of::<u_int>() as libc::c_ulong,
                Some(
                    sglob_comp
                        as unsafe extern "C" fn(
                            *const libc::c_void,
                            *const libc::c_void,
                        ) -> libc::c_int,
                ),
            );
            sort_glob = 0 as *mut _ssh_compat_glob_t;
        }
        get_remote_user_groups_from_glob(conn, &mut g);
        let mut current_block_55: u64;
        j = 0 as libc::c_int as u_int;
        while j < nentries && interrupted == 0 {
            i = *indices.offset(j as isize);
            fname = path_strip(*(g.gl_pathv).offset(i as isize), strip_path);
            if lflag & 0x1 as libc::c_int != 0 {
                if (*(g.gl_statv).offset(i as isize)).is_null() {
                    crate::log::sshlog(
                        b"sftp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(
                            b"do_globbed_ls\0",
                        ))
                        .as_ptr(),
                        1033 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"no libc::stat information for %s\0" as *const u8 as *const libc::c_char,
                        fname,
                    );
                    libc::free(fname as *mut libc::c_void);
                    current_block_55 = 9853141518545631134;
                } else {
                    lname = ls_file(
                        fname,
                        *(g.gl_statv).offset(i as isize),
                        1 as libc::c_int,
                        lflag & 0x100 as libc::c_int,
                        ruser_name((**(g.gl_statv).offset(i as isize)).st_uid),
                        rgroup_name((**(g.gl_statv).offset(i as isize)).st_gid),
                    );
                    mprintf(b"%s\n\0" as *const u8 as *const libc::c_char, lname);
                    libc::free(lname as *mut libc::c_void);
                    current_block_55 = 313581471991351815;
                }
            } else {
                mprintf(
                    b"%-*s\0" as *const u8 as *const libc::c_char,
                    colspace,
                    fname,
                );
                if c >= columns {
                    printf(b"\n\0" as *const u8 as *const libc::c_char);
                    c = 1 as libc::c_int as u_int;
                } else {
                    c = c.wrapping_add(1);
                    c;
                }
                current_block_55 = 313581471991351815;
            }
            match current_block_55 {
                313581471991351815 => {
                    libc::free(fname as *mut libc::c_void);
                }
                _ => {}
            }
            j = j.wrapping_add(1);
            j;
        }
        if lflag & 0x1 as libc::c_int == 0 && c != 1 as libc::c_int as libc::c_uint {
            printf(b"\n\0" as *const u8 as *const libc::c_char);
        }
    }
    if g.gl_pathc != 0 {
        _ssh__compat_globfree(&mut g);
    }
    libc::free(indices as *mut libc::c_void);
    return 0 as libc::c_int;
}
unsafe extern "C" fn do_df(
    mut conn: *mut sftp_conn,
    mut path: *const libc::c_char,
    mut hflag: libc::c_int,
    mut iflag: libc::c_int,
) -> libc::c_int {
    let mut st: sftp_statvfs = sftp_statvfs {
        f_bsize: 0,
        f_frsize: 0,
        f_blocks: 0,
        f_bfree: 0,
        f_bavail: 0,
        f_files: 0,
        f_ffree: 0,
        f_favail: 0,
        f_fsid: 0,
        f_flag: 0,
        f_namemax: 0,
    };
    let mut s_used: [libc::c_char; 7] = [0; 7];
    let mut s_avail: [libc::c_char; 7] = [0; 7];
    let mut s_root: [libc::c_char; 7] = [0; 7];
    let mut s_total: [libc::c_char; 7] = [0; 7];
    let mut s_icapacity: [libc::c_char; 16] = [0; 16];
    let mut s_dcapacity: [libc::c_char; 16] = [0; 16];
    if do_statvfs(conn, path, &mut st, 1 as libc::c_int) == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    if st.f_files == 0 as libc::c_int as libc::c_ulong {
        strlcpy(
            s_icapacity.as_mut_ptr(),
            b"ERR\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
        );
    } else {
        libc::snprintf(
            s_icapacity.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 16]>() as usize,
            b"%3llu%%\0" as *const u8 as *const libc::c_char,
            (100 as libc::c_int as libc::c_ulong)
                .wrapping_mul((st.f_files).wrapping_sub(st.f_ffree))
                .wrapping_div(st.f_files) as libc::c_ulonglong,
        );
    }
    if st.f_blocks == 0 as libc::c_int as libc::c_ulong {
        strlcpy(
            s_dcapacity.as_mut_ptr(),
            b"ERR\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
        );
    } else {
        libc::snprintf(
            s_dcapacity.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 16]>() as usize,
            b"%3llu%%\0" as *const u8 as *const libc::c_char,
            (100 as libc::c_int as libc::c_ulong)
                .wrapping_mul((st.f_blocks).wrapping_sub(st.f_bfree))
                .wrapping_div(st.f_blocks) as libc::c_ulonglong,
        );
    }
    if iflag != 0 {
        printf(
            b"     Inodes        Used       Avail      (root)    %%Capacity\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"%11llu %11llu %11llu %11llu         %s\n\0" as *const u8 as *const libc::c_char,
            st.f_files as libc::c_ulonglong,
            (st.f_files).wrapping_sub(st.f_ffree) as libc::c_ulonglong,
            st.f_favail as libc::c_ulonglong,
            st.f_ffree as libc::c_ulonglong,
            s_icapacity.as_mut_ptr(),
        );
    } else if hflag != 0 {
        strlcpy(
            s_used.as_mut_ptr(),
            b"error\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 7]>() as libc::c_ulong,
        );
        strlcpy(
            s_avail.as_mut_ptr(),
            b"error\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 7]>() as libc::c_ulong,
        );
        strlcpy(
            s_root.as_mut_ptr(),
            b"error\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 7]>() as libc::c_ulong,
        );
        strlcpy(
            s_total.as_mut_ptr(),
            b"error\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 7]>() as libc::c_ulong,
        );
        fmt_scaled(
            (st.f_blocks)
                .wrapping_sub(st.f_bfree)
                .wrapping_mul(st.f_frsize) as libc::c_longlong,
            s_used.as_mut_ptr(),
        );
        fmt_scaled(
            (st.f_bavail).wrapping_mul(st.f_frsize) as libc::c_longlong,
            s_avail.as_mut_ptr(),
        );
        fmt_scaled(
            (st.f_bfree).wrapping_mul(st.f_frsize) as libc::c_longlong,
            s_root.as_mut_ptr(),
        );
        fmt_scaled(
            (st.f_blocks).wrapping_mul(st.f_frsize) as libc::c_longlong,
            s_total.as_mut_ptr(),
        );
        printf(
            b"    Size     Used    Avail   (root)    %%Capacity\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"%7sB %7sB %7sB %7sB         %s\n\0" as *const u8 as *const libc::c_char,
            s_total.as_mut_ptr(),
            s_used.as_mut_ptr(),
            s_avail.as_mut_ptr(),
            s_root.as_mut_ptr(),
            s_dcapacity.as_mut_ptr(),
        );
    } else {
        printf(
            b"        Size         Used        Avail       (root)    %%Capacity\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"%12llu %12llu %12llu %12llu         %s\n\0" as *const u8 as *const libc::c_char,
            (st.f_frsize)
                .wrapping_mul(st.f_blocks)
                .wrapping_div(1024 as libc::c_int as libc::c_ulong)
                as libc::c_ulonglong,
            (st.f_frsize)
                .wrapping_mul((st.f_blocks).wrapping_sub(st.f_bfree))
                .wrapping_div(1024 as libc::c_int as libc::c_ulong)
                as libc::c_ulonglong,
            (st.f_frsize)
                .wrapping_mul(st.f_bavail)
                .wrapping_div(1024 as libc::c_int as libc::c_ulong)
                as libc::c_ulonglong,
            (st.f_frsize)
                .wrapping_mul(st.f_bfree)
                .wrapping_div(1024 as libc::c_int as libc::c_ulong)
                as libc::c_ulonglong,
            s_dcapacity.as_mut_ptr(),
        );
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn undo_glob_escape(mut s: *mut libc::c_char) {
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    j = 0 as libc::c_int as size_t;
    i = j;
    loop {
        if *s.offset(i as isize) as libc::c_int == '\0' as i32 {
            *s.offset(j as isize) = '\0' as i32 as libc::c_char;
            return;
        }
        if *s.offset(i as isize) as libc::c_int != '\\' as i32 {
            let fresh3 = i;
            i = i.wrapping_add(1);
            let fresh4 = j;
            j = j.wrapping_add(1);
            *s.offset(fresh4 as isize) = *s.offset(fresh3 as isize);
        } else {
            i = i.wrapping_add(1);
            i;
            match *s.offset(i as isize) as libc::c_int {
                63 | 91 | 42 | 92 => {
                    let fresh5 = i;
                    i = i.wrapping_add(1);
                    let fresh6 = j;
                    j = j.wrapping_add(1);
                    *s.offset(fresh6 as isize) = *s.offset(fresh5 as isize);
                }
                0 => {
                    let fresh7 = j;
                    j = j.wrapping_add(1);
                    *s.offset(fresh7 as isize) = '\\' as i32 as libc::c_char;
                    *s.offset(j as isize) = '\0' as i32 as libc::c_char;
                    return;
                }
                _ => {
                    let fresh8 = j;
                    j = j.wrapping_add(1);
                    *s.offset(fresh8 as isize) = '\\' as i32 as libc::c_char;
                    let fresh9 = i;
                    i = i.wrapping_add(1);
                    let fresh10 = j;
                    j = j.wrapping_add(1);
                    *s.offset(fresh10 as isize) = *s.offset(fresh9 as isize);
                }
            }
        }
    }
}
unsafe extern "C" fn makeargv(
    mut arg: *const libc::c_char,
    mut argcp: *mut libc::c_int,
    mut sloppy: libc::c_int,
    mut lastquote: *mut libc::c_char,
    mut terminated: *mut u_int,
) -> *mut *mut libc::c_char {
    let mut current_block: u64;
    let mut argc: libc::c_int = 0;
    let mut quot: libc::c_int = 0;
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    static mut argvs: [libc::c_char; 8192] = [0; 8192];
    static mut argv: [*mut libc::c_char; 129] =
        [0 as *const libc::c_char as *mut libc::c_char; 129];
    let mut state: C2RustUnnamed_12 = MA_START;
    let mut q: C2RustUnnamed_12 = MA_START;
    argc = 0 as libc::c_int;
    *argcp = argc;
    if !(strlen(arg)
        > (::core::mem::size_of::<[libc::c_char; 8192]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong))
    {
        if !terminated.is_null() {
            *terminated = 1 as libc::c_int as u_int;
        }
        if !lastquote.is_null() {
            *lastquote = '\0' as i32 as libc::c_char;
        }
        state = MA_START;
        j = 0 as libc::c_int as size_t;
        i = j;
        loop {
            if argc as size_t
                >= (::core::mem::size_of::<[*mut libc::c_char; 129]>() as libc::c_ulong)
                    .wrapping_div(::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong)
            {
                crate::log::sshlog(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"makeargv\0"))
                        .as_ptr(),
                    1205 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Too many arguments.\0" as *const u8 as *const libc::c_char,
                );
                return 0 as *mut *mut libc::c_char;
            }
            if *(*__ctype_b_loc())
                .offset(*arg.offset(i as isize) as libc::c_uchar as libc::c_int as isize)
                as libc::c_int
                & _ISspace as libc::c_int as libc::c_ushort as libc::c_int
                != 0
            {
                if state as libc::c_uint == MA_UNQUOTED as libc::c_int as libc::c_uint {
                    let fresh11 = j;
                    j = j.wrapping_add(1);
                    argvs[fresh11 as usize] = '\0' as i32 as libc::c_char;
                    argc += 1;
                    argc;
                    state = MA_START;
                } else if state as libc::c_uint != MA_START as libc::c_int as libc::c_uint {
                    let fresh12 = j;
                    j = j.wrapping_add(1);
                    argvs[fresh12 as usize] = *arg.offset(i as isize);
                }
            } else if *arg.offset(i as isize) as libc::c_int == '"' as i32
                || *arg.offset(i as isize) as libc::c_int == '\'' as i32
            {
                q = (if *arg.offset(i as isize) as libc::c_int == '"' as i32 {
                    MA_DQUOTE as libc::c_int
                } else {
                    MA_SQUOTE as libc::c_int
                }) as C2RustUnnamed_12;
                if state as libc::c_uint == MA_START as libc::c_int as libc::c_uint {
                    argv[argc as usize] = argvs.as_mut_ptr().offset(j as isize);
                    state = q;
                    if !lastquote.is_null() {
                        *lastquote = *arg.offset(i as isize);
                    }
                } else if state as libc::c_uint == MA_UNQUOTED as libc::c_int as libc::c_uint {
                    state = q;
                } else if state as libc::c_uint == q as libc::c_uint {
                    state = MA_UNQUOTED;
                } else {
                    let fresh13 = j;
                    j = j.wrapping_add(1);
                    argvs[fresh13 as usize] = *arg.offset(i as isize);
                }
            } else if *arg.offset(i as isize) as libc::c_int == '\\' as i32 {
                if state as libc::c_uint == MA_SQUOTE as libc::c_int as libc::c_uint
                    || state as libc::c_uint == MA_DQUOTE as libc::c_int as libc::c_uint
                {
                    quot = if state as libc::c_uint == MA_SQUOTE as libc::c_int as libc::c_uint {
                        '\'' as i32
                    } else {
                        '"' as i32
                    };
                    if *arg.offset(i.wrapping_add(1 as libc::c_int as libc::c_ulong) as isize)
                        as libc::c_int
                        == quot
                    {
                        i = i.wrapping_add(1);
                        i;
                        let fresh14 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh14 as usize] = *arg.offset(i as isize);
                    } else if *arg
                        .offset(i.wrapping_add(1 as libc::c_int as libc::c_ulong) as isize)
                        as libc::c_int
                        == '?' as i32
                        || *arg.offset(i.wrapping_add(1 as libc::c_int as libc::c_ulong) as isize)
                            as libc::c_int
                            == '[' as i32
                        || *arg.offset(i.wrapping_add(1 as libc::c_int as libc::c_ulong) as isize)
                            as libc::c_int
                            == '*' as i32
                    {
                        if j >= (::core::mem::size_of::<[libc::c_char; 8192]>() as libc::c_ulong)
                            .wrapping_sub(5 as libc::c_int as libc::c_ulong)
                        {
                            current_block = 3039557260611480687;
                            break;
                        }
                        let fresh15 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh15 as usize] = '\\' as i32 as libc::c_char;
                        let fresh16 = i;
                        i = i.wrapping_add(1);
                        let fresh17 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh17 as usize] = *arg.offset(fresh16 as isize);
                        let fresh18 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh18 as usize] = '\\' as i32 as libc::c_char;
                        let fresh19 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh19 as usize] = *arg.offset(i as isize);
                    } else {
                        let fresh20 = i;
                        i = i.wrapping_add(1);
                        let fresh21 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh21 as usize] = *arg.offset(fresh20 as isize);
                        let fresh22 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh22 as usize] = *arg.offset(i as isize);
                    }
                } else {
                    if state as libc::c_uint == MA_START as libc::c_int as libc::c_uint {
                        argv[argc as usize] = argvs.as_mut_ptr().offset(j as isize);
                        state = MA_UNQUOTED;
                        if !lastquote.is_null() {
                            *lastquote = '\0' as i32 as libc::c_char;
                        }
                    }
                    if *arg.offset(i.wrapping_add(1 as libc::c_int as libc::c_ulong) as isize)
                        as libc::c_int
                        == '?' as i32
                        || *arg.offset(i.wrapping_add(1 as libc::c_int as libc::c_ulong) as isize)
                            as libc::c_int
                            == '[' as i32
                        || *arg.offset(i.wrapping_add(1 as libc::c_int as libc::c_ulong) as isize)
                            as libc::c_int
                            == '*' as i32
                        || *arg.offset(i.wrapping_add(1 as libc::c_int as libc::c_ulong) as isize)
                            as libc::c_int
                            == '\\' as i32
                    {
                        let fresh23 = i;
                        i = i.wrapping_add(1);
                        let fresh24 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh24 as usize] = *arg.offset(fresh23 as isize);
                        let fresh25 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh25 as usize] = *arg.offset(i as isize);
                    } else {
                        i = i.wrapping_add(1);
                        i;
                        let fresh26 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh26 as usize] = *arg.offset(i as isize);
                    }
                }
            } else {
                if *arg.offset(i as isize) as libc::c_int == '#' as i32 {
                    if state as libc::c_uint == MA_SQUOTE as libc::c_int as libc::c_uint
                        || state as libc::c_uint == MA_DQUOTE as libc::c_int as libc::c_uint
                    {
                        let fresh27 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh27 as usize] = *arg.offset(i as isize);
                        current_block = 16231175055492490595;
                    } else {
                        current_block = 5681206264379648677;
                    }
                } else if *arg.offset(i as isize) as libc::c_int == '\0' as i32 {
                    if state as libc::c_uint == MA_SQUOTE as libc::c_int as libc::c_uint
                        || state as libc::c_uint == MA_DQUOTE as libc::c_int as libc::c_uint
                    {
                        if sloppy != 0 {
                            state = MA_UNQUOTED;
                            if !terminated.is_null() {
                                *terminated = 0 as libc::c_int as u_int;
                            }
                        } else {
                            crate::log::sshlog(
                                b"sftp.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(
                                    b"makeargv\0",
                                ))
                                .as_ptr(),
                                1292 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"Unterminated quoted argument\0" as *const u8
                                    as *const libc::c_char,
                            );
                            return 0 as *mut *mut libc::c_char;
                        }
                        current_block = 5681206264379648677;
                    } else {
                        current_block = 5681206264379648677;
                    }
                } else {
                    if state as libc::c_uint == MA_START as libc::c_int as libc::c_uint {
                        argv[argc as usize] = argvs.as_mut_ptr().offset(j as isize);
                        state = MA_UNQUOTED;
                        if !lastquote.is_null() {
                            *lastquote = '\0' as i32 as libc::c_char;
                        }
                    }
                    if (state as libc::c_uint == MA_SQUOTE as libc::c_int as libc::c_uint
                        || state as libc::c_uint == MA_DQUOTE as libc::c_int as libc::c_uint)
                        && (*arg.offset(i as isize) as libc::c_int == '?' as i32
                            || *arg.offset(i as isize) as libc::c_int == '[' as i32
                            || *arg.offset(i as isize) as libc::c_int == '*' as i32)
                    {
                        if j >= (::core::mem::size_of::<[libc::c_char; 8192]>() as libc::c_ulong)
                            .wrapping_sub(3 as libc::c_int as libc::c_ulong)
                        {
                            current_block = 3039557260611480687;
                            break;
                        }
                        let fresh29 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh29 as usize] = '\\' as i32 as libc::c_char;
                        let fresh30 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh30 as usize] = *arg.offset(i as isize);
                    } else {
                        let fresh31 = j;
                        j = j.wrapping_add(1);
                        argvs[fresh31 as usize] = *arg.offset(i as isize);
                    }
                    current_block = 16231175055492490595;
                }
                match current_block {
                    16231175055492490595 => {}
                    _ => {
                        if state as libc::c_uint == MA_UNQUOTED as libc::c_int as libc::c_uint {
                            let fresh28 = j;
                            j = j.wrapping_add(1);
                            argvs[fresh28 as usize] = '\0' as i32 as libc::c_char;
                            argc += 1;
                            argc;
                        }
                        current_block = 2472048668343472511;
                        break;
                    }
                }
            }
            i = i.wrapping_add(1);
            i;
        }
        match current_block {
            3039557260611480687 => {}
            _ => {
                *argcp = argc;
                return argv.as_mut_ptr();
            }
        }
    }
    crate::log::sshlog(
        b"sftp.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"makeargv\0")).as_ptr(),
        1194 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"string too long\0" as *const u8 as *const libc::c_char,
    );
    return 0 as *mut *mut libc::c_char;
}
unsafe extern "C" fn parse_args(
    mut cpp: *mut *const libc::c_char,
    mut ignore_errors: *mut libc::c_int,
    mut disable_echo: *mut libc::c_int,
    mut aflag: *mut libc::c_int,
    mut fflag: *mut libc::c_int,
    mut hflag: *mut libc::c_int,
    mut iflag: *mut libc::c_int,
    mut lflag: *mut libc::c_int,
    mut pflag: *mut libc::c_int,
    mut rflag: *mut libc::c_int,
    mut sflag: *mut libc::c_int,
    mut n_arg: *mut libc::c_ulong,
    mut path1: *mut *mut libc::c_char,
    mut path2: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut cmd: *const libc::c_char = 0 as *const libc::c_char;
    let mut cp: *const libc::c_char = *cpp;
    let mut cp2: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut argv: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut base: libc::c_int = 0 as libc::c_int;
    let mut ll: libc::c_longlong = 0;
    let mut path1_mandatory: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    let mut cmdnum: libc::c_int = 0;
    let mut optidx: libc::c_int = 0;
    let mut argc: libc::c_int = 0;
    cp = cp.offset(strspn(cp, b" \t\r\n\0" as *const u8 as *const libc::c_char) as isize);
    *ignore_errors = 0 as libc::c_int;
    *disable_echo = 0 as libc::c_int;
    while *cp as libc::c_int != '\0' as i32 {
        if *cp as libc::c_int == '-' as i32 {
            *ignore_errors = 1 as libc::c_int;
        } else {
            if !(*cp as libc::c_int == '@' as i32) {
                break;
            }
            *disable_echo = 1 as libc::c_int;
        }
        cp = cp.offset(1);
        cp;
    }
    cp = cp.offset(strspn(cp, b" \t\r\n\0" as *const u8 as *const libc::c_char) as isize);
    if *cp as libc::c_int == '\0' as i32 || *cp as libc::c_int == '#' as i32 {
        return 0 as libc::c_int;
    }
    argv = makeargv(
        cp,
        &mut argc,
        0 as libc::c_int,
        0 as *mut libc::c_char,
        0 as *mut u_int,
    );
    if argv.is_null() {
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int;
    while !(cmds[i as usize].c).is_null() {
        if !(*argv.offset(0 as libc::c_int as isize)).is_null()
            && strcasecmp(cmds[i as usize].c, *argv.offset(0 as libc::c_int as isize))
                == 0 as libc::c_int
        {
            break;
        }
        i += 1;
        i;
    }
    cmdnum = cmds[i as usize].n;
    cmd = cmds[i as usize].c;
    if *cp as libc::c_int == '!' as i32 {
        cp = cp.offset(1);
        cp;
        cmdnum = I_SHELL as libc::c_int;
    } else if cmdnum == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sftp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"parse_args\0")).as_ptr(),
            1381 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Invalid command.\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    *pflag = 0 as libc::c_int;
    *lflag = *pflag;
    *iflag = *lflag;
    *hflag = *iflag;
    *fflag = *hflag;
    *aflag = *fflag;
    *sflag = 0 as libc::c_int;
    *rflag = *sflag;
    *path2 = 0 as *mut libc::c_char;
    *path1 = *path2;
    optidx = 1 as libc::c_int;
    match cmdnum {
        7 | 20 | 22 | 17 => {
            optidx = parse_getput_flags(cmd, argv, argc, aflag, fflag, pflag, rflag);
            if optidx == -(1 as libc::c_int) {
                return -(1 as libc::c_int);
            }
            if argc - optidx < 1 as libc::c_int {
                crate::log::sshlog(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"parse_args\0"))
                        .as_ptr(),
                    1401 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"You must specify at least one path after a %s command.\0" as *const u8
                        as *const libc::c_char,
                    cmd,
                );
                return -(1 as libc::c_int);
            }
            *path1 = xstrdup(*argv.offset(optidx as isize));
            if argc - optidx > 1 as libc::c_int {
                *path2 = xstrdup(*argv.offset((optidx + 1 as libc::c_int) as isize));
                undo_glob_escape(*path2);
            }
            current_block = 17769492591016358583;
        }
        10 => {
            optidx = parse_link_flags(cmd, argv, argc, sflag);
            if optidx == -(1 as libc::c_int) {
                return -(1 as libc::c_int);
            }
            current_block = 11651839663461973003;
        }
        5 => {
            optidx = parse_no_flags(cmd, argv, argc);
            if optidx == -(1 as libc::c_int) {
                return -(1 as libc::c_int);
            }
            current_block = 11651839663461973003;
        }
        21 => {
            optidx = parse_rename_flags(cmd, argv, argc, lflag);
            if optidx == -(1 as libc::c_int) {
                return -(1 as libc::c_int);
            }
            current_block = 11651839663461973003;
        }
        26 => {
            optidx = parse_no_flags(cmd, argv, argc);
            if optidx == -(1 as libc::c_int) {
                return -(1 as libc::c_int);
            }
            current_block = 11651839663461973003;
        }
        23 | 16 | 24 | 12 => {
            path1_mandatory = 1 as libc::c_int;
            current_block = 10412952180452415515;
        }
        1 | 9 => {
            current_block = 10412952180452415515;
        }
        6 => {
            optidx = parse_df_flags(cmd, argv, argc, hflag, iflag);
            if optidx == -(1 as libc::c_int) {
                return -(1 as libc::c_int);
            }
            if argc - optidx < 1 as libc::c_int {
                *path1 = 0 as *mut libc::c_char;
            } else {
                *path1 = xstrdup(*argv.offset(optidx as isize));
                undo_glob_escape(*path1);
            }
            current_block = 17769492591016358583;
        }
        14 => {
            optidx = parse_ls_flags(argv, argc, lflag);
            if optidx == -(1 as libc::c_int) {
                return -(1 as libc::c_int);
            }
            if argc - optidx > 0 as libc::c_int {
                *path1 = xstrdup(*argv.offset(optidx as isize));
            }
            current_block = 17769492591016358583;
        }
        11 => {
            cp = cp
                .offset(strlen(cmd) as isize)
                .offset(strspn(cp, b" \t\r\n\0" as *const u8 as *const libc::c_char) as isize);
            current_block = 17769492591016358583;
        }
        25 => {
            current_block = 17769492591016358583;
        }
        15 | 3 => {
            base = 8 as libc::c_int;
            current_block = 17860910445150148172;
        }
        4 | 2 => {
            current_block = 17860910445150148172;
        }
        19 | 18 | 13 | 8 | 27 | 28 => {
            optidx = parse_no_flags(cmd, argv, argc);
            if optidx == -(1 as libc::c_int) {
                return -(1 as libc::c_int);
            }
            current_block = 17769492591016358583;
        }
        _ => {
            sshfatal(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"parse_args\0"))
                    .as_ptr(),
                1529 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Command not implemented\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    match current_block {
        10412952180452415515 => {
            optidx = parse_no_flags(cmd, argv, argc);
            if optidx == -(1 as libc::c_int) {
                return -(1 as libc::c_int);
            }
            if argc - optidx < 1 as libc::c_int {
                if !(path1_mandatory == 0) {
                    crate::log::sshlog(
                        b"sftp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                            b"parse_args\0",
                        ))
                        .as_ptr(),
                        1454 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"You must specify a path after a %s command.\0" as *const u8
                            as *const libc::c_char,
                        cmd,
                    );
                    return -(1 as libc::c_int);
                }
            } else {
                *path1 = xstrdup(*argv.offset(optidx as isize));
                if cmdnum != I_RM as libc::c_int {
                    undo_glob_escape(*path1);
                }
            }
        }
        11651839663461973003 => {
            if argc - optidx < 2 as libc::c_int {
                crate::log::sshlog(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"parse_args\0"))
                        .as_ptr(),
                    1430 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"You must specify two paths after a %s command.\0" as *const u8
                        as *const libc::c_char,
                    cmd,
                );
                return -(1 as libc::c_int);
            }
            *path1 = xstrdup(*argv.offset(optidx as isize));
            *path2 = xstrdup(*argv.offset((optidx + 1 as libc::c_int) as isize));
            undo_glob_escape(*path1);
            undo_glob_escape(*path2);
        }
        17860910445150148172 => {
            optidx = parse_ch_flags(cmd, argv, argc, hflag);
            if optidx == -(1 as libc::c_int) {
                return -(1 as libc::c_int);
            }
            if argc - optidx < 1 as libc::c_int {
                current_block = 10949423776451605237;
            } else {
                *libc::__errno_location() = 0 as libc::c_int;
                ll = strtoll(*argv.offset(optidx as isize), &mut cp2, base);
                if cp2 == *argv.offset(optidx as isize)
                    || *cp2 as libc::c_int != '\0' as i32
                    || (ll == -(9223372036854775807 as libc::c_longlong) - 1 as libc::c_longlong
                        || ll == 9223372036854775807 as libc::c_longlong)
                        && *libc::__errno_location() == 34 as libc::c_int
                    || ll < 0 as libc::c_int as libc::c_longlong
                    || ll > 4294967295 as libc::c_uint as libc::c_longlong
                {
                    current_block = 10949423776451605237;
                } else {
                    *n_arg = ll as libc::c_ulong;
                    if cmdnum == I_LUMASK as libc::c_int {
                        current_block = 17769492591016358583;
                    } else {
                        if argc - optidx < 2 as libc::c_int {
                            crate::log::sshlog(
                                b"sftp.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                    b"parse_args\0",
                                ))
                                .as_ptr(),
                                1514 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"You must specify a path after a %s command.\0" as *const u8
                                    as *const libc::c_char,
                                cmd,
                            );
                            return -(1 as libc::c_int);
                        }
                        *path1 = xstrdup(*argv.offset((optidx + 1 as libc::c_int) as isize));
                        current_block = 17769492591016358583;
                    }
                }
            }
            match current_block {
                17769492591016358583 => {}
                _ => {
                    crate::log::sshlog(
                        b"sftp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                            b"parse_args\0",
                        ))
                        .as_ptr(),
                        1505 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"You must supply a numeric argument to the %s command.\0" as *const u8
                            as *const libc::c_char,
                        cmd,
                    );
                    return -(1 as libc::c_int);
                }
            }
        }
        _ => {}
    }
    *cpp = cp;
    return cmdnum;
}
unsafe extern "C" fn parse_dispatch_command(
    mut conn: *mut sftp_conn,
    mut cmd: *const libc::c_char,
    mut pwd: *mut *mut libc::c_char,
    mut startdir: *const libc::c_char,
    mut err_abort: libc::c_int,
    mut echo_command: libc::c_int,
) -> libc::c_int {
    let mut ocmd: *const libc::c_char = cmd;
    let mut path1: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut path2: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ignore_errors: libc::c_int = 0 as libc::c_int;
    let mut disable_echo: libc::c_int = 1 as libc::c_int;
    let mut aflag: libc::c_int = 0 as libc::c_int;
    let mut fflag: libc::c_int = 0 as libc::c_int;
    let mut hflag: libc::c_int = 0 as libc::c_int;
    let mut iflag: libc::c_int = 0 as libc::c_int;
    let mut lflag: libc::c_int = 0 as libc::c_int;
    let mut pflag: libc::c_int = 0 as libc::c_int;
    let mut rflag: libc::c_int = 0 as libc::c_int;
    let mut sflag: libc::c_int = 0 as libc::c_int;
    let mut cmdnum: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut n_arg: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
    let mut a: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    let mut aa: *mut Attrib = 0 as *mut Attrib;
    let mut path_buf: [libc::c_char; 4096] = [0; 4096];
    let mut err: libc::c_int = 0 as libc::c_int;
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
    path2 = 0 as *mut libc::c_char;
    path1 = path2;
    cmdnum = parse_args(
        &mut cmd,
        &mut ignore_errors,
        &mut disable_echo,
        &mut aflag,
        &mut fflag,
        &mut hflag,
        &mut iflag,
        &mut lflag,
        &mut pflag,
        &mut rflag,
        &mut sflag,
        &mut n_arg,
        &mut path1,
        &mut path2,
    );
    if ignore_errors != 0 as libc::c_int {
        err_abort = 0 as libc::c_int;
    }
    if echo_command != 0 && disable_echo == 0 {
        mprintf(b"sftp> %s\n\0" as *const u8 as *const libc::c_char, ocmd);
    }
    memset(
        &mut g as *mut _ssh_compat_glob_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<_ssh_compat_glob_t>() as libc::c_ulong,
    );
    let mut current_block_116: u64;
    match cmdnum {
        0 => {
            current_block_116 = 7337917895049117968;
        }
        -1 => {
            err = -(1 as libc::c_int);
            current_block_116 = 7337917895049117968;
        }
        20 => {
            aflag = 1 as libc::c_int;
            current_block_116 = 11185642904128448456;
        }
        7 => {
            current_block_116 = 11185642904128448456;
        }
        22 => {
            aflag = 1 as libc::c_int;
            current_block_116 = 7830150306102224148;
        }
        17 => {
            current_block_116 = 7830150306102224148;
        }
        5 => {
            path1 = make_absolute(path1, *pwd);
            path2 = make_absolute(path2, *pwd);
            err = do_copy(conn, path1, path2);
            current_block_116 = 7337917895049117968;
        }
        21 => {
            path1 = make_absolute(path1, *pwd);
            path2 = make_absolute(path2, *pwd);
            err = do_rename(conn, path1, path2, lflag);
            current_block_116 = 7337917895049117968;
        }
        26 => {
            sflag = 1 as libc::c_int;
            current_block_116 = 9918873640902903466;
        }
        10 => {
            current_block_116 = 9918873640902903466;
        }
        23 => {
            path1 = make_absolute_pwd_glob(path1, *pwd);
            remote_glob(conn, path1, 0x10 as libc::c_int, None, &mut g);
            i = 0 as libc::c_int;
            while !(*(g.gl_pathv).offset(i as isize)).is_null() && interrupted == 0 {
                if quiet == 0 {
                    mprintf(
                        b"Removing %s\n\0" as *const u8 as *const libc::c_char,
                        *(g.gl_pathv).offset(i as isize),
                    );
                }
                err = do_rm(conn, *(g.gl_pathv).offset(i as isize));
                if err != 0 as libc::c_int && err_abort != 0 {
                    break;
                }
                i += 1;
                i;
            }
            current_block_116 = 7337917895049117968;
        }
        16 => {
            path1 = make_absolute(path1, *pwd);
            attrib_clear(&mut a);
            a.flags |= 0x4 as libc::c_int as libc::c_uint;
            a.perm = 0o777 as libc::c_int as u_int32_t;
            err = do_mkdir(conn, path1, &mut a, 1 as libc::c_int);
            current_block_116 = 7337917895049117968;
        }
        24 => {
            path1 = make_absolute(path1, *pwd);
            err = do_rmdir(conn, path1);
            current_block_116 = 7337917895049117968;
        }
        1 => {
            if path1.is_null() || *path1 as libc::c_int == '\0' as i32 {
                path1 = xstrdup(startdir);
            }
            path1 = make_absolute(path1, *pwd);
            tmp = do_realpath(conn, path1);
            if tmp.is_null() {
                err = 1 as libc::c_int;
            } else {
                aa = do_stat(conn, tmp, 0 as libc::c_int);
                if aa.is_null() {
                    libc::free(tmp as *mut libc::c_void);
                    err = 1 as libc::c_int;
                } else if (*aa).flags & 0x4 as libc::c_int as libc::c_uint == 0 {
                    crate::log::sshlog(
                        b"sftp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                            b"parse_dispatch_command\0",
                        ))
                        .as_ptr(),
                        1642 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Can't change directory: Can't check target\0" as *const u8
                            as *const libc::c_char,
                    );
                    libc::free(tmp as *mut libc::c_void);
                    err = 1 as libc::c_int;
                } else if !((*aa).perm & 0o170000 as libc::c_int as libc::c_uint
                    == 0o40000 as libc::c_int as libc::c_uint)
                {
                    crate::log::sshlog(
                        b"sftp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                            b"parse_dispatch_command\0",
                        ))
                        .as_ptr(),
                        1649 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Can't change directory: \"%s\" is not a directory\0" as *const u8
                            as *const libc::c_char,
                        tmp,
                    );
                    libc::free(tmp as *mut libc::c_void);
                    err = 1 as libc::c_int;
                } else {
                    libc::free(*pwd as *mut libc::c_void);
                    *pwd = tmp;
                }
            }
            current_block_116 = 7337917895049117968;
        }
        14 => {
            if path1.is_null() {
                do_ls_dir(conn, *pwd, *pwd, lflag);
            } else {
                tmp = 0 as *mut libc::c_char;
                if path_absolute(path1) == 0 {
                    tmp = *pwd;
                }
                path1 = make_absolute_pwd_glob(path1, *pwd);
                err = do_globbed_ls(conn, path1, tmp, lflag);
            }
            current_block_116 = 7337917895049117968;
        }
        6 => {
            if path1.is_null() {
                path1 = xstrdup(*pwd);
            }
            path1 = make_absolute(path1, *pwd);
            err = do_df(conn, path1, hflag, iflag);
            current_block_116 = 7337917895049117968;
        }
        9 => {
            if path1.is_null() || *path1 as libc::c_int == '\0' as i32 {
                path1 = xstrdup(b"~\0" as *const u8 as *const libc::c_char);
            }
            tmp = tilde_expand_filename(path1, libc::getuid());
            libc::free(path1 as *mut libc::c_void);
            path1 = tmp;
            if chdir(path1) == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"parse_dispatch_command\0",
                    ))
                    .as_ptr(),
                    1686 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Couldn't change local directory to \"%s\": %s\0" as *const u8
                        as *const libc::c_char,
                    path1,
                    strerror(*libc::__errno_location()),
                );
                err = 1 as libc::c_int;
            }
            current_block_116 = 7337917895049117968;
        }
        12 => {
            if libc::mkdir(path1, 0o777 as libc::c_int as __mode_t) == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"parse_dispatch_command\0",
                    ))
                    .as_ptr(),
                    1693 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Couldn't create local directory \"%s\": %s\0" as *const u8
                        as *const libc::c_char,
                    path1,
                    strerror(*libc::__errno_location()),
                );
                err = 1 as libc::c_int;
            }
            current_block_116 = 7337917895049117968;
        }
        11 => {
            local_do_ls(cmd);
            current_block_116 = 7337917895049117968;
        }
        25 => {
            local_do_shell(cmd);
            current_block_116 = 7337917895049117968;
        }
        15 => {
            libc::umask(n_arg as __mode_t);
            printf(
                b"Local umask: %03lo\n\0" as *const u8 as *const libc::c_char,
                n_arg,
            );
            current_block_116 = 7337917895049117968;
        }
        3 => {
            path1 = make_absolute_pwd_glob(path1, *pwd);
            attrib_clear(&mut a);
            a.flags |= 0x4 as libc::c_int as libc::c_uint;
            a.perm = n_arg as u_int32_t;
            remote_glob(conn, path1, 0x10 as libc::c_int, None, &mut g);
            i = 0 as libc::c_int;
            while !(*(g.gl_pathv).offset(i as isize)).is_null() && interrupted == 0 {
                if quiet == 0 {
                    mprintf(
                        b"Changing mode on %s\n\0" as *const u8 as *const libc::c_char,
                        *(g.gl_pathv).offset(i as isize),
                    );
                }
                err = if hflag != 0 {
                    Some(
                        do_lsetstat
                            as unsafe extern "C" fn(
                                *mut sftp_conn,
                                *const libc::c_char,
                                *mut Attrib,
                            ) -> libc::c_int,
                    )
                } else {
                    Some(
                        do_setstat
                            as unsafe extern "C" fn(
                                *mut sftp_conn,
                                *const libc::c_char,
                                *mut Attrib,
                            ) -> libc::c_int,
                    )
                }
                .expect("non-null function pointer")(
                    conn,
                    *(g.gl_pathv).offset(i as isize),
                    &mut a,
                );
                if err != 0 as libc::c_int && err_abort != 0 {
                    break;
                }
                i += 1;
                i;
            }
            current_block_116 = 7337917895049117968;
        }
        4 | 2 => {
            path1 = make_absolute_pwd_glob(path1, *pwd);
            remote_glob(conn, path1, 0x10 as libc::c_int, None, &mut g);
            i = 0 as libc::c_int;
            while !(*(g.gl_pathv).offset(i as isize)).is_null() && interrupted == 0 {
                aa = if hflag != 0 {
                    Some(
                        do_lstat
                            as unsafe extern "C" fn(
                                *mut sftp_conn,
                                *const libc::c_char,
                                libc::c_int,
                            ) -> *mut Attrib,
                    )
                } else {
                    Some(
                        do_stat
                            as unsafe extern "C" fn(
                                *mut sftp_conn,
                                *const libc::c_char,
                                libc::c_int,
                            ) -> *mut Attrib,
                    )
                }
                .expect("non-null function pointer")(
                    conn,
                    *(g.gl_pathv).offset(i as isize),
                    0 as libc::c_int,
                );
                if aa.is_null() {
                    if err_abort != 0 {
                        err = -(1 as libc::c_int);
                        break;
                    }
                } else if (*aa).flags & 0x2 as libc::c_int as libc::c_uint == 0 {
                    crate::log::sshlog(
                        b"sftp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                            b"parse_dispatch_command\0",
                        ))
                        .as_ptr(),
                        1738 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Can't get current ownership of remote file \"%s\"\0" as *const u8
                            as *const libc::c_char,
                        *(g.gl_pathv).offset(i as isize),
                    );
                    if err_abort != 0 {
                        err = -(1 as libc::c_int);
                        break;
                    }
                } else {
                    (*aa).flags &= 0x2 as libc::c_int as libc::c_uint;
                    if cmdnum == I_CHOWN as libc::c_int {
                        if quiet == 0 {
                            mprintf(
                                b"Changing owner on %s\n\0" as *const u8 as *const libc::c_char,
                                *(g.gl_pathv).offset(i as isize),
                            );
                        }
                        (*aa).uid = n_arg as u_int32_t;
                    } else {
                        if quiet == 0 {
                            mprintf(
                                b"Changing group on %s\n\0" as *const u8 as *const libc::c_char,
                                *(g.gl_pathv).offset(i as isize),
                            );
                        }
                        (*aa).gid = n_arg as u_int32_t;
                    }
                    err = if hflag != 0 {
                        Some(
                            do_lsetstat
                                as unsafe extern "C" fn(
                                    *mut sftp_conn,
                                    *const libc::c_char,
                                    *mut Attrib,
                                )
                                    -> libc::c_int,
                        )
                    } else {
                        Some(
                            do_setstat
                                as unsafe extern "C" fn(
                                    *mut sftp_conn,
                                    *const libc::c_char,
                                    *mut Attrib,
                                )
                                    -> libc::c_int,
                        )
                    }
                    .expect("non-null function pointer")(
                        conn,
                        *(g.gl_pathv).offset(i as isize),
                        aa,
                    );
                    if err != 0 as libc::c_int && err_abort != 0 {
                        break;
                    }
                }
                i += 1;
                i;
            }
            current_block_116 = 7337917895049117968;
        }
        18 => {
            mprintf(
                b"Remote working directory: %s\n\0" as *const u8 as *const libc::c_char,
                *pwd,
            );
            current_block_116 = 7337917895049117968;
        }
        13 => {
            if (getcwd(
                path_buf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
            ))
            .is_null()
            {
                crate::log::sshlog(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"parse_dispatch_command\0",
                    ))
                    .as_ptr(),
                    1768 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Couldn't get local cwd: %s\0" as *const u8 as *const libc::c_char,
                    strerror(*libc::__errno_location()),
                );
                err = -(1 as libc::c_int);
            } else {
                mprintf(
                    b"Local working directory: %s\n\0" as *const u8 as *const libc::c_char,
                    path_buf.as_mut_ptr(),
                );
            }
            current_block_116 = 7337917895049117968;
        }
        19 => {
            current_block_116 = 7337917895049117968;
        }
        8 => {
            help();
            current_block_116 = 7337917895049117968;
        }
        27 => {
            printf(
                b"SFTP protocol version %u\n\0" as *const u8 as *const libc::c_char,
                sftp_proto_version(conn),
            );
            current_block_116 = 7337917895049117968;
        }
        28 => {
            showprogress = (showprogress == 0) as libc::c_int;
            if showprogress != 0 {
                printf(b"Progress meter enabled\n\0" as *const u8 as *const libc::c_char);
            } else {
                printf(b"Progress meter disabled\n\0" as *const u8 as *const libc::c_char);
            }
            current_block_116 = 7337917895049117968;
        }
        _ => {
            sshfatal(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"parse_dispatch_command\0",
                ))
                .as_ptr(),
                1791 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%d is not implemented\0" as *const u8 as *const libc::c_char,
                cmdnum,
            );
        }
    }
    match current_block_116 {
        9918873640902903466 => {
            if sflag == 0 {
                path1 = make_absolute(path1, *pwd);
            }
            path2 = make_absolute(path2, *pwd);
            err = if sflag != 0 {
                Some(
                    do_symlink
                        as unsafe extern "C" fn(
                            *mut sftp_conn,
                            *const libc::c_char,
                            *const libc::c_char,
                        ) -> libc::c_int,
                )
            } else {
                Some(
                    do_hardlink
                        as unsafe extern "C" fn(
                            *mut sftp_conn,
                            *const libc::c_char,
                            *const libc::c_char,
                        ) -> libc::c_int,
                )
            }
            .expect("non-null function pointer")(conn, path1, path2);
        }
        11185642904128448456 => {
            err = process_get(conn, path1, path2, *pwd, pflag, rflag, aflag, fflag);
        }
        7830150306102224148 => {
            err = process_put(conn, path1, path2, *pwd, pflag, rflag, aflag, fflag);
        }
        _ => {}
    }
    if g.gl_pathc != 0 {
        _ssh__compat_globfree(&mut g);
    }
    libc::free(path1 as *mut libc::c_void);
    libc::free(path2 as *mut libc::c_void);
    if err_abort != 0 && err != 0 as libc::c_int {
        return -(1 as libc::c_int);
    } else if cmdnum == I_QUIT as libc::c_int {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn interactive_loop(
    mut conn: *mut sftp_conn,
    mut file1: *mut libc::c_char,
    mut file2: *mut libc::c_char,
) -> libc::c_int {
    let mut remote_path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut dir: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut startdir: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cmd: [libc::c_char; 2048] = [0; 2048];
    let mut err: libc::c_int = 0;
    let mut interactive: libc::c_int = 0;
    let mut el: *mut libc::c_void = 0 as *mut libc::c_void;
    remote_path = do_realpath(conn, b".\0" as *const u8 as *const libc::c_char);
    if remote_path.is_null() {
        sshfatal(
            b"sftp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"interactive_loop\0"))
                .as_ptr(),
            2239 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Need cwd\0" as *const u8 as *const libc::c_char,
        );
    }
    startdir = xstrdup(remote_path);
    if !file1.is_null() {
        dir = xstrdup(file1);
        dir = make_absolute(dir, remote_path);
        if remote_is_dir(conn, dir) != 0 && file2.is_null() {
            if quiet == 0 {
                mprintf(
                    b"Changing to: %s\n\0" as *const u8 as *const libc::c_char,
                    dir,
                );
            }
            libc::snprintf(
                cmd.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 2048]>() as usize,
                b"cd \"%s\"\0" as *const u8 as *const libc::c_char,
                dir,
            );
            if parse_dispatch_command(
                conn,
                cmd.as_mut_ptr(),
                &mut remote_path,
                startdir,
                1 as libc::c_int,
                0 as libc::c_int,
            ) != 0 as libc::c_int
            {
                libc::free(dir as *mut libc::c_void);
                libc::free(startdir as *mut libc::c_void);
                libc::free(remote_path as *mut libc::c_void);
                libc::free(conn as *mut libc::c_void);
                return -(1 as libc::c_int);
            }
        } else {
            libc::snprintf(
                cmd.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 2048]>() as usize,
                b"get%s %s%s%s\0" as *const u8 as *const libc::c_char,
                if global_aflag != 0 {
                    b" -a\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                dir,
                if file2.is_null() {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    b" \0" as *const u8 as *const libc::c_char
                },
                if file2.is_null() {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    file2 as *const libc::c_char
                },
            );
            err = parse_dispatch_command(
                conn,
                cmd.as_mut_ptr(),
                &mut remote_path,
                startdir,
                1 as libc::c_int,
                0 as libc::c_int,
            );
            libc::free(dir as *mut libc::c_void);
            libc::free(startdir as *mut libc::c_void);
            libc::free(remote_path as *mut libc::c_void);
            libc::free(conn as *mut libc::c_void);
            return err;
        }
        libc::free(dir as *mut libc::c_void);
    }
    setvbuf(
        stdout,
        0 as *mut libc::c_char,
        1 as libc::c_int,
        0 as libc::c_int as size_t,
    );
    setvbuf(
        infile,
        0 as *mut libc::c_char,
        1 as libc::c_int,
        0 as libc::c_int as size_t,
    );
    interactive = (batchmode == 0 && isatty(0 as libc::c_int) != 0) as libc::c_int;
    err = 0 as libc::c_int;
    loop {
        let mut sa: sigaction = sigaction {
            __sigaction_handler: C2RustUnnamed_10 { sa_handler: None },
            sa_mask: __sigset_t { __val: [0; 16] },
            sa_flags: 0,
            sa_restorer: None,
        };
        ::core::ptr::write_volatile(&mut interrupted as *mut sig_atomic_t, 0 as libc::c_int);
        memset(
            &mut sa as *mut sigaction as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<sigaction>() as libc::c_ulong,
        );
        sa.__sigaction_handler.sa_handler = if interactive != 0 {
            Some(read_interrupt as unsafe extern "C" fn(libc::c_int) -> ())
        } else {
            Some(killchild as unsafe extern "C" fn(libc::c_int) -> ())
        };
        if sigaction(2 as libc::c_int, &mut sa, 0 as *mut sigaction) == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"interactive_loop\0"))
                    .as_ptr(),
                2288 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"sigaction(%s): %s\0" as *const u8 as *const libc::c_char,
                strsignal(2 as libc::c_int),
                strerror(*libc::__errno_location()),
            );
            break;
        } else {
            if el.is_null() {
                if interactive != 0 {
                    printf(b"sftp> \0" as *const u8 as *const libc::c_char);
                }
                if (fgets(
                    cmd.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 2048]>() as libc::c_ulong as libc::c_int,
                    infile,
                ))
                .is_null()
                {
                    if interactive != 0 {
                        printf(b"\n\0" as *const u8 as *const libc::c_char);
                    }
                    if interrupted != 0 {
                        continue;
                    } else {
                        break;
                    }
                }
            }
            cmd[strcspn(
                cmd.as_mut_ptr(),
                b"\n\0" as *const u8 as *const libc::c_char,
            ) as usize] = '\0' as i32 as libc::c_char;
            ::core::ptr::write_volatile(&mut interrupted as *mut sig_atomic_t, 0 as libc::c_int);
            ssh_signal(
                2 as libc::c_int,
                Some(cmd_interrupt as unsafe extern "C" fn(libc::c_int) -> ()),
            );
            err = parse_dispatch_command(
                conn,
                cmd.as_mut_ptr(),
                &mut remote_path,
                startdir,
                batchmode,
                (interactive == 0 && el.is_null()) as libc::c_int,
            );
            if err != 0 as libc::c_int {
                break;
            }
        }
    }
    ssh_signal(17 as libc::c_int, None);
    libc::free(remote_path as *mut libc::c_void);
    libc::free(startdir as *mut libc::c_void);
    libc::free(conn as *mut libc::c_void);
    return if err >= 0 as libc::c_int {
        0 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
unsafe extern "C" fn connect_to_server(
    mut path: *mut libc::c_char,
    mut args: *mut *mut libc::c_char,
    mut in_0: *mut libc::c_int,
    mut out: *mut libc::c_int,
) {
    let mut c_in: libc::c_int = 0;
    let mut c_out: libc::c_int = 0;
    let mut inout: [libc::c_int; 2] = [0; 2];
    if libc::socketpair(
        1 as libc::c_int,
        SOCK_STREAM as libc::c_int,
        0 as libc::c_int,
        inout.as_mut_ptr(),
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"sftp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"connect_to_server\0"))
                .as_ptr(),
            2363 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::socketpair: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    *out = inout[0 as libc::c_int as usize];
    *in_0 = *out;
    c_out = inout[1 as libc::c_int as usize];
    c_in = c_out;
    ::core::ptr::write_volatile(&mut sshpid as *mut pid_t, libc::fork());
    if ::core::ptr::read_volatile::<pid_t>(&sshpid as *const pid_t) == -(1 as libc::c_int) {
        sshfatal(
            b"sftp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"connect_to_server\0"))
                .as_ptr(),
            2369 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::fork: %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    } else if sshpid == 0 as libc::c_int {
        if libc::dup2(c_in, 0 as libc::c_int) == -(1 as libc::c_int)
            || libc::dup2(c_out, 1 as libc::c_int) == -(1 as libc::c_int)
        {
            libc::fprintf(
                stderr,
                b"libc::dup2: %s\n\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
            libc::_exit(1 as libc::c_int);
        }
        close(*in_0);
        close(*out);
        close(c_in);
        close(c_out);
        ssh_signal(
            2 as libc::c_int,
            ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
                1 as libc::c_int as libc::intptr_t,
            ),
        );
        ssh_signal(15 as libc::c_int, None);
        execvp(path, args as *const *mut libc::c_char);
        libc::fprintf(
            stderr,
            b"exec: %s: %s\n\0" as *const u8 as *const libc::c_char,
            path,
            strerror(*libc::__errno_location()),
        );
        libc::_exit(1 as libc::c_int);
    }
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
    ssh_signal(
        17 as libc::c_int,
        Some(sigchld_handler as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    close(c_in);
    close(c_out);
}
unsafe extern "C" fn usage() {
    extern "C" {
        #[link_name = "__progname"]
        static mut __progname_0: *mut libc::c_char;
    }
    libc::fprintf(
        stderr,
        b"usage: %s [-46AaCfNpqrv] [-B buffer_size] [-b batchfile] [-c cipher]\n          [-D sftp_server_command] [-F ssh_config] [-i identity_file]\n          [-J destination] [-l limit] [-o ssh_option] [-P port]\n          [-R num_requests] [-S program] [-s subsystem | sftp_server]\n          [-X sftp_option] destination\n\0"
            as *const u8 as *const libc::c_char,
        __progname,
    );
    libc::exit(1 as libc::c_int);
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut in_0: libc::c_int = 0;
    let mut out: libc::c_int = 0;
    let mut ch: libc::c_int = 0;
    let mut err: libc::c_int = 0;
    let mut tmp: libc::c_int = 0;
    let mut port: libc::c_int = -(1 as libc::c_int);
    let mut noisy: libc::c_int = 0 as libc::c_int;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cpp: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut file2: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut debug_level: libc::c_int = 0 as libc::c_int;
    let mut file1: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sftp_server: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ssh_program: *mut libc::c_char =
        b"/usr/local/bin/ssh\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    let mut sftp_direct: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut errstr: *const libc::c_char = 0 as *const libc::c_char;
    let mut ll: LogLevel = SYSLOG_LEVEL_INFO;
    let mut args: arglist = arglist {
        list: 0 as *mut *mut libc::c_char,
        num: 0,
        nalloc: 0,
    };
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    extern "C" {
        #[link_name = "BSDoptarg"]
        static mut BSDoptarg_0: *mut libc::c_char;
    }
    let mut conn: *mut sftp_conn = 0 as *mut sftp_conn;
    let mut copy_buffer_len: size_t = 0 as libc::c_int as size_t;
    let mut num_requests: size_t = 0 as libc::c_int as size_t;
    let mut llv: libc::c_longlong = 0;
    let mut limit_kbps: libc::c_longlong = 0 as libc::c_int as libc::c_longlong;
    crate::misc::sanitise_stdfd();
    msetlocale();
    __progname =
        crate::openbsd_compat::bsd_misc::ssh_get_progname(*argv.offset(0 as libc::c_int as isize));
    memset(
        &mut args as *mut arglist as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<arglist>() as libc::c_ulong,
    );
    args.list = 0 as *mut *mut libc::c_char;
    crate::misc::addargs(
        &mut args as *mut arglist,
        b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        ssh_program,
    );
    crate::misc::addargs(
        &mut args as *mut arglist,
        b"-oForwardX11 no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    crate::misc::addargs(
        &mut args as *mut arglist,
        b"-oPermitLocalCommand no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    crate::misc::addargs(
        &mut args as *mut arglist,
        b"-oClearAllForwardings yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    ll = SYSLOG_LEVEL_INFO;
    infile = stdin;
    loop {
        ch = BSDgetopt(
            argc,
            argv,
            b"1246AafhNpqrvCc:D:i:l:o:s:S:b:B:F:J:P:R:X:\0" as *const u8 as *const libc::c_char,
        );
        if !(ch != -(1 as libc::c_int)) {
            break;
        }
        match ch {
            65 | 52 | 54 | 67 => {
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"-%c\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    ch,
                );
            }
            70 | 74 | 99 | 105 | 111 => {
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
            113 => {
                ll = SYSLOG_LEVEL_ERROR;
                quiet = 1 as libc::c_int;
                showprogress = 0 as libc::c_int;
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"-%c\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    ch,
                );
            }
            80 => {
                port = crate::misc::a2port(BSDoptarg);
                if port <= 0 as libc::c_int {
                    sshfatal(
                        b"sftp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        2482 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Bad port \"%s\"\n\0" as *const u8 as *const libc::c_char,
                        BSDoptarg,
                    );
                }
            }
            118 => {
                if debug_level < 3 as libc::c_int {
                    crate::misc::addargs(
                        &mut args as *mut arglist,
                        b"-v\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    );
                    ll = (SYSLOG_LEVEL_DEBUG1 as libc::c_int + debug_level) as LogLevel;
                }
                debug_level += 1;
                debug_level;
            }
            49 => {
                sshfatal(
                    b"sftp.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    2492 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"SSH protocol v.1 is no longer supported\0" as *const u8
                        as *const libc::c_char,
                );
            }
            50 => {}
            97 => {
                global_aflag = 1 as libc::c_int;
            }
            66 => {
                copy_buffer_len = strtol(BSDoptarg, &mut cp, 10 as libc::c_int) as size_t;
                if copy_buffer_len == 0 as libc::c_int as libc::c_ulong
                    || *cp as libc::c_int != '\0' as i32
                {
                    sshfatal(
                        b"sftp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        2503 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Invalid buffer size \"%s\"\0" as *const u8 as *const libc::c_char,
                        BSDoptarg,
                    );
                }
            }
            98 => {
                if batchmode != 0 {
                    sshfatal(
                        b"sftp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        2507 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Batch file already specified.\0" as *const u8 as *const libc::c_char,
                    );
                }
                if strcmp(BSDoptarg, b"-\0" as *const u8 as *const libc::c_char) != 0 as libc::c_int
                    && {
                        infile = fopen(BSDoptarg, b"r\0" as *const u8 as *const libc::c_char);
                        infile.is_null()
                    }
                {
                    sshfatal(
                        b"sftp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        2512 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"%s (%s).\0" as *const u8 as *const libc::c_char,
                        strerror(*libc::__errno_location()),
                        BSDoptarg,
                    );
                }
                showprogress = 0 as libc::c_int;
                batchmode = 1 as libc::c_int;
                quiet = batchmode;
                crate::misc::addargs(
                    &mut args as *mut arglist,
                    b"-obatchmode yes\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                );
            }
            102 => {
                global_fflag = 1 as libc::c_int;
            }
            78 => {
                noisy = 1 as libc::c_int;
            }
            112 => {
                global_pflag = 1 as libc::c_int;
            }
            68 => {
                sftp_direct = BSDoptarg;
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
            }
            114 => {
                global_rflag = 1 as libc::c_int;
            }
            82 => {
                num_requests = strtol(BSDoptarg, &mut cp, 10 as libc::c_int) as size_t;
                if num_requests == 0 as libc::c_int as libc::c_ulong
                    || *cp as libc::c_int != '\0' as i32
                {
                    sshfatal(
                        b"sftp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        2543 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Invalid number of requests \"%s\"\0" as *const u8 as *const libc::c_char,
                        BSDoptarg,
                    );
                }
            }
            115 => {
                sftp_server = BSDoptarg;
            }
            83 => {
                ssh_program = BSDoptarg;
                crate::misc::replacearg(
                    &mut args as *mut arglist,
                    0 as libc::c_int as u_int,
                    b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    ssh_program,
                );
            }
            88 => {
                if strncmp(
                    BSDoptarg,
                    b"buffer=\0" as *const u8 as *const libc::c_char,
                    7 as libc::c_int as libc::c_ulong,
                ) == 0 as libc::c_int
                {
                    r = scan_scaled(BSDoptarg.offset(7 as libc::c_int as isize), &mut llv);
                    if r == 0 as libc::c_int
                        && (llv <= 0 as libc::c_int as libc::c_longlong
                            || llv > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_longlong)
                    {
                        r = -(1 as libc::c_int);
                        *libc::__errno_location() = 22 as libc::c_int;
                    }
                    if r == -(1 as libc::c_int) {
                        sshfatal(
                            b"sftp.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            2562 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Invalid buffer size \"%s\": %s\0" as *const u8 as *const libc::c_char,
                            BSDoptarg.offset(7 as libc::c_int as isize),
                            strerror(*libc::__errno_location()),
                        );
                    }
                    copy_buffer_len = llv as size_t;
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
                            b"sftp.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            2570 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Invalid number of requests \"%s\": %s\0" as *const u8
                                as *const libc::c_char,
                            BSDoptarg.offset(10 as libc::c_int as isize),
                            errstr,
                        );
                    }
                    num_requests = llv as size_t;
                } else {
                    sshfatal(
                        b"sftp.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        2574 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Invalid -X option\0" as *const u8 as *const libc::c_char,
                    );
                }
            }
            104 | _ => {
                usage();
            }
        }
    }
    crate::misc::addargs(
        &mut args as *mut arglist,
        b"-oForwardAgent no\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    if isatty(2 as libc::c_int) == 0 {
        showprogress = 0 as libc::c_int;
    }
    if noisy != 0 {
        quiet = 0 as libc::c_int;
    }
    log_init(
        *argv.offset(0 as libc::c_int as isize),
        ll,
        SYSLOG_FACILITY_USER,
        1 as libc::c_int,
    );
    if sftp_direct.is_null() {
        if BSDoptind == argc || argc > BSDoptind + 2 as libc::c_int {
            usage();
        }
        argv = argv.offset(BSDoptind as isize);
        match parse_uri(
            b"sftp\0" as *const u8 as *const libc::c_char,
            *argv,
            &mut user,
            &mut host,
            &mut tmp,
            &mut file1,
        ) {
            -1 => {
                usage();
            }
            0 => {
                if tmp != -(1 as libc::c_int) {
                    port = tmp;
                }
            }
            _ => {
                if !(parse_user_host_path(*argv, &mut user, &mut host, &mut file1)
                    == 0 as libc::c_int)
                {
                    if !(parse_user_host_port(*argv, &mut user, &mut host, 0 as *mut libc::c_int)
                        == 0 as libc::c_int)
                    {
                        host = xstrdup(*argv);
                        host = cleanhostname(host);
                    }
                }
            }
        }
        file2 = *argv.offset(1 as libc::c_int as isize);
        if *host == 0 {
            libc::fprintf(
                stderr,
                b"Missing hostname\n\0" as *const u8 as *const libc::c_char,
            );
            usage();
        }
        if port != -(1 as libc::c_int) {
            crate::misc::addargs(
                &mut args as *mut arglist,
                b"-oPort %d\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                port,
            );
        }
        if !user.is_null() {
            crate::misc::addargs(
                &mut args as *mut arglist,
                b"-l\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            );
            crate::misc::addargs(
                &mut args as *mut arglist,
                b"%s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                user,
            );
        }
        if sftp_server.is_null() || (strchr(sftp_server, '/' as i32)).is_null() {
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
            if !sftp_server.is_null() {
                sftp_server as *const libc::c_char
            } else {
                b"sftp\0" as *const u8 as *const libc::c_char
            },
        );
        connect_to_server(ssh_program, args.list, &mut in_0, &mut out);
    } else {
        r = argv_split(sftp_direct, &mut tmp, &mut cpp, 1 as libc::c_int);
        if r != 0 as libc::c_int {
            sshfatal(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2647 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"Parse -D arguments\0" as *const u8 as *const libc::c_char,
            );
        }
        if (*cpp.offset(0 as libc::c_int as isize)).is_null() {
            sshfatal(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2649 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"No sftp server specified via -D\0" as *const u8 as *const libc::c_char,
            );
        }
        connect_to_server(
            *cpp.offset(0 as libc::c_int as isize),
            cpp,
            &mut in_0,
            &mut out,
        );
        argv_free(cpp, tmp);
    }
    crate::misc::freeargs(&mut args);
    conn = do_init(
        in_0,
        out,
        copy_buffer_len as u_int,
        num_requests as u_int,
        limit_kbps as u_int64_t,
    );
    if conn.is_null() {
        sshfatal(
            b"sftp.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2657 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Couldn't initialise connection to server\0" as *const u8 as *const libc::c_char,
        );
    }
    if quiet == 0 {
        if sftp_direct.is_null() {
            libc::fprintf(
                stderr,
                b"Connected to %s.\n\0" as *const u8 as *const libc::c_char,
                host,
            );
        } else {
            libc::fprintf(
                stderr,
                b"Attached to %s.\n\0" as *const u8 as *const libc::c_char,
                sftp_direct,
            );
        }
    }
    err = interactive_loop(conn, file1, file2);
    shutdown(in_0, SHUT_RDWR as libc::c_int);
    shutdown(out, SHUT_RDWR as libc::c_int);
    close(in_0);
    close(out);
    if batchmode != 0 {
        fclose(infile);
    }
    while libc::waitpid(sshpid, 0 as *mut libc::c_int, 0 as libc::c_int) == -(1 as libc::c_int)
        && sshpid > 1 as libc::c_int
    {
        if *libc::__errno_location() != 4 as libc::c_int {
            sshfatal(
                b"sftp.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2681 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Couldn't wait for ssh process: %s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
    }
    libc::exit(if err == 0 as libc::c_int {
        0 as libc::c_int
    } else {
        1 as libc::c_int
    });
}
pub fn main() {
    let mut args: Vec<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::core::ptr::null_mut());
    unsafe {
        ::std::process::exit(main_0(
            (args.len() - 1) as libc::c_int,
            args.as_mut_ptr() as *mut *mut libc::c_char,
        ) as i32)
    }
}
