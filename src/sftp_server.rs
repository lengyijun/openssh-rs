use crate::atomicio::atomicio;
use crate::sftp_common::Attrib;

use ::libc;
use libc::close;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;

    pub type __dirstream;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn futimes(__fd: libc::c_int, __tvp: *const libc::timeval) -> libc::c_int;

    fn lstat(__file: *const libc::c_char, __buf: *mut libc::stat) -> libc::c_int;
    fn fchmodat(
        __fd: libc::c_int,
        __file: *const libc::c_char,
        __mode: __mode_t,
        __flag: libc::c_int,
    ) -> libc::c_int;

    fn utimensat(
        __fd: libc::c_int,
        __path: *const libc::c_char,
        __times: *const libc::timespec,
        __flags: libc::c_int,
    ) -> libc::c_int;

    fn getpwnam(__name: *const libc::c_char) -> *mut libc::passwd;
    fn platform_disable_tracing(_: libc::c_int);
    fn platform_pledge_sftp_server();
    fn lseek(__fd: libc::c_int, __offset: __off_t, __whence: libc::c_int) -> __off_t;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn chown(__file: *const libc::c_char, __owner: __uid_t, __group: __gid_t) -> libc::c_int;
    fn fchown(__fd: libc::c_int, __owner: __uid_t, __group: __gid_t) -> libc::c_int;
    fn fchownat(
        __fd: libc::c_int,
        __file: *const libc::c_char,
        __owner: __uid_t,
        __group: __gid_t,
        __flag: libc::c_int,
    ) -> libc::c_int;
    fn chdir(__path: *const libc::c_char) -> libc::c_int;
    fn getcwd(__buf: *mut libc::c_char, __size: size_t) -> *mut libc::c_char;

    fn link(__from: *const libc::c_char, __to: *const libc::c_char) -> libc::c_int;
    fn symlink(__from: *const libc::c_char, __to: *const libc::c_char) -> libc::c_int;
    fn readlink(__path: *const libc::c_char, __buf: *mut libc::c_char, __len: size_t) -> ssize_t;
    fn unlink(__name: *const libc::c_char) -> libc::c_int;
    fn rmdir(__path: *const libc::c_char) -> libc::c_int;
    static mut BSDoptarg: *mut libc::c_char;

    fn fsync(__fd: libc::c_int) -> libc::c_int;
    fn truncate(__file: *const libc::c_char, __length: __off_t) -> libc::c_int;

    fn rename(__old: *const libc::c_char, __new: *const libc::c_char) -> libc::c_int;

    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;

    static mut stderr: *mut libc::FILE;
    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;

    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: libc::c_int) -> libc::c_int;
    fn getrlimit(__resource: __rlimit_resource_t, __rlimits: *mut rlimit) -> libc::c_int;
    fn statvfs(__file: *const libc::c_char, __buf: *mut statvfs) -> libc::c_int;
    fn fstatvfs(__fildes: libc::c_int, __buf: *mut statvfs) -> libc::c_int;

    fn getgrgid(__gid: __gid_t) -> *mut group;
    fn strtol(_: *const libc::c_char, _: *mut *mut libc::c_char, _: libc::c_int) -> libc::c_long;
    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;

    fn realloc(_: *mut libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;

    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;

    fn strftime(
        __s: *mut libc::c_char,
        __maxsize: size_t,
        __format: *const libc::c_char,
        __tp: *const tm,
    ) -> size_t;
    fn localtime(__timer: *const time_t) -> *mut tm;

    fn xreallocarray(_: *mut libc::c_void, _: size_t, _: size_t) -> *mut libc::c_void;

    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut crate::sshbuf::sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_string(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_string(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;

    fn sshbuf_put_u32(buf: *mut crate::sshbuf::sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_put_u64(buf: *mut crate::sshbuf::sshbuf, val: u_int64_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut crate::sshbuf::sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut crate::sshbuf::sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_get_u64(buf: *mut crate::sshbuf::sshbuf, valp: *mut u_int64_t) -> libc::c_int;
    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_consume(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_check_reserve(buf: *const crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_ptr(buf: *const crate::sshbuf::sshbuf) -> *const u_char;

    fn sshbuf_froms(
        buf: *mut crate::sshbuf::sshbuf,
        bufp: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;

    fn ssh_err(n: libc::c_int) -> *const libc::c_char;

    fn log_facility_number(_: *mut libc::c_char) -> SyslogFacility;
    fn log_level_number(_: *mut libc::c_char) -> LogLevel;

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
    fn tilde_expand(_: *const libc::c_char, _: uid_t, _: *mut *mut libc::c_char) -> libc::c_int;
    fn tilde_expand_filename(_: *const libc::c_char, _: uid_t) -> *mut libc::c_char;
    fn percent_expand(_: *const libc::c_char, _: ...) -> *mut libc::c_char;
    fn pwcopy(_: *mut libc::passwd) -> *mut libc::passwd;
    fn get_u32(_: *const libc::c_void) -> u_int32_t;
    fn put_u32(_: *mut libc::c_void, _: u_int32_t);
    fn match_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut u_int,
    ) -> *mut libc::c_char;
    fn attrib_clear(_: *mut Attrib);
    fn stat_to_attrib(_: *const libc::stat, _: *mut Attrib);
    fn decode_attrib(_: *mut crate::sshbuf::sshbuf, _: *mut Attrib) -> libc::c_int;
    fn encode_attrib(_: *mut crate::sshbuf::sshbuf, _: *const Attrib) -> libc::c_int;
    fn ls_file(
        _: *const libc::c_char,
        _: *const libc::stat,
        _: libc::c_int,
        _: libc::c_int,
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> *mut libc::c_char;
    fn sftp_realpath(_: *const libc::c_char, _: *mut libc::c_char) -> *mut libc::c_char;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
pub type __int32_t = libc::c_int;
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
pub type __rlim_t = libc::c_ulong;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __fsblkcnt_t = libc::c_ulong;
pub type __fsfilcnt_t = libc::c_ulong;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type gid_t = __gid_t;
pub type mode_t = __mode_t;
pub type uid_t = __uid_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type int32_t = __int32_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;

pub type uint64_t = __uint64_t;

pub type _IO_lock_t = ();

pub type nfds_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pollfd {
    pub fd: libc::c_int,
    pub events: libc::c_short,
    pub revents: libc::c_short,
}
pub type __rlimit_resource = libc::c_uint;
pub const __RLIM_NLIMITS: __rlimit_resource = 16;
pub const __RLIMIT_NLIMITS: __rlimit_resource = 16;
pub const __RLIMIT_RTTIME: __rlimit_resource = 15;
pub const __RLIMIT_RTPRIO: __rlimit_resource = 14;
pub const __RLIMIT_NICE: __rlimit_resource = 13;
pub const __RLIMIT_MSGQUEUE: __rlimit_resource = 12;
pub const __RLIMIT_SIGPENDING: __rlimit_resource = 11;
pub const __RLIMIT_LOCKS: __rlimit_resource = 10;
pub const __RLIMIT_MEMLOCK: __rlimit_resource = 8;
pub const __RLIMIT_NPROC: __rlimit_resource = 6;
pub const RLIMIT_AS: __rlimit_resource = 9;
pub const __RLIMIT_OFILE: __rlimit_resource = 7;
pub const RLIMIT_NOFILE: __rlimit_resource = 7;
pub const __RLIMIT_RSS: __rlimit_resource = 5;
pub const RLIMIT_CORE: __rlimit_resource = 4;
pub const RLIMIT_STACK: __rlimit_resource = 3;
pub const RLIMIT_DATA: __rlimit_resource = 2;
pub const RLIMIT_FSIZE: __rlimit_resource = 1;
pub const RLIMIT_CPU: __rlimit_resource = 0;
pub type rlim_t = __rlim_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rlimit {
    pub rlim_cur: rlim_t,
    pub rlim_max: rlim_t,
}
pub type __rlimit_resource_t = __rlimit_resource;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct statvfs {
    pub f_bsize: libc::c_ulong,
    pub f_frsize: libc::c_ulong,
    pub f_blocks: __fsblkcnt_t,
    pub f_bfree: __fsblkcnt_t,
    pub f_bavail: __fsblkcnt_t,
    pub f_files: __fsfilcnt_t,
    pub f_ffree: __fsfilcnt_t,
    pub f_favail: __fsfilcnt_t,
    pub f_fsid: libc::c_ulong,
    pub f_flag: libc::c_ulong,
    pub f_namemax: libc::c_ulong,
    pub __f_spare: [libc::c_int; 6],
}
pub type C2RustUnnamed = libc::c_uint;
pub const ST_RELATIME: C2RustUnnamed = 4096;
pub const ST_NODIRATIME: C2RustUnnamed = 2048;
pub const ST_NOATIME: C2RustUnnamed = 1024;
pub const ST_IMMUTABLE: C2RustUnnamed = 512;
pub const ST_APPEND: C2RustUnnamed = 256;
pub const ST_WRITE: C2RustUnnamed = 128;
pub const ST_MANDLOCK: C2RustUnnamed = 64;
pub const ST_SYNCHRONOUS: C2RustUnnamed = 16;
pub const ST_NOEXEC: C2RustUnnamed = 8;
pub const ST_NODEV: C2RustUnnamed = 4;
pub const ST_NOSUID: C2RustUnnamed = 2;
pub const ST_RDONLY: C2RustUnnamed = 1;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct group {
    pub gr_name: *mut libc::c_char,
    pub gr_passwd: *mut libc::c_char,
    pub gr_gid: __gid_t,
    pub gr_mem: *mut *mut libc::c_char,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Handle {
    pub use_0: libc::c_int,
    pub dirp: *mut libc::DIR,
    pub fd: libc::c_int,
    pub flags: libc::c_int,
    pub name: *mut libc::c_char,
    pub bytes_read: u_int64_t,
    pub bytes_write: u_int64_t,
    pub next_unused: libc::c_int,
}
pub const HANDLE_FILE: C2RustUnnamed_0 = 2;
pub const HANDLE_DIR: C2RustUnnamed_0 = 1;
pub const HANDLE_UNUSED: C2RustUnnamed_0 = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sftp_handler {
    pub name: *const libc::c_char,
    pub ext_name: *const libc::c_char,
    pub type_0: u_int,
    pub handler: Option<unsafe extern "C" fn(u_int32_t) -> ()>,
    pub does_write: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Stat {
    pub name: *mut libc::c_char,
    pub long_name: *mut libc::c_char,
    pub attrib: Attrib,
}

pub type C2RustUnnamed_0 = libc::c_uint;
static mut log_level: LogLevel = SYSLOG_LEVEL_ERROR;
static mut pw: *mut libc::passwd = 0 as *const libc::passwd as *mut libc::passwd;
static mut client_addr: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
pub static mut iqueue: *mut crate::sshbuf::sshbuf =
    0 as *const crate::sshbuf::sshbuf as *mut crate::sshbuf::sshbuf;
pub static mut oqueue: *mut crate::sshbuf::sshbuf =
    0 as *const crate::sshbuf::sshbuf as *mut crate::sshbuf::sshbuf;
static mut version: u_int = 0;
static mut init_done: libc::c_int = 0;
static mut readonly: libc::c_int = 0;
static mut request_allowlist: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut request_denylist: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut handlers: [sftp_handler; 19] = unsafe {
    [
        {
            let mut init = sftp_handler {
                name: b"open\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 3 as libc::c_int as u_int,
                handler: Some(process_open as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"close\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 4 as libc::c_int as u_int,
                handler: Some(process_close as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"read\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 5 as libc::c_int as u_int,
                handler: Some(process_read as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"write\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 6 as libc::c_int as u_int,
                handler: Some(process_write as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 1 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"lstat\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 7 as libc::c_int as u_int,
                handler: Some(process_lstat as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"libc::fstat\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 8 as libc::c_int as u_int,
                handler: Some(process_fstat as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"setstat\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 9 as libc::c_int as u_int,
                handler: Some(process_setstat as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 1 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"fsetstat\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 10 as libc::c_int as u_int,
                handler: Some(process_fsetstat as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 1 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"libc::opendir\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 11 as libc::c_int as u_int,
                handler: Some(process_opendir as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"libc::readdir\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 12 as libc::c_int as u_int,
                handler: Some(process_readdir as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"remove\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 13 as libc::c_int as u_int,
                handler: Some(process_remove as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 1 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"mkdir\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 14 as libc::c_int as u_int,
                handler: Some(process_mkdir as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 1 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"rmdir\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 15 as libc::c_int as u_int,
                handler: Some(process_rmdir as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 1 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"realpath\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 16 as libc::c_int as u_int,
                handler: Some(process_realpath as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"libc::stat\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 17 as libc::c_int as u_int,
                handler: Some(process_stat as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"rename\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 18 as libc::c_int as u_int,
                handler: Some(process_rename as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 1 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"readlink\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 19 as libc::c_int as u_int,
                handler: Some(process_readlink as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"symlink\0" as *const u8 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 20 as libc::c_int as u_int,
                handler: Some(process_symlink as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 1 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: 0 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 0 as libc::c_int as u_int,
                handler: None,
                does_write: 0 as libc::c_int,
            };
            init
        },
    ]
};
static mut extended_handlers: [sftp_handler; 12] = unsafe {
    [
        {
            let mut init = sftp_handler {
                name: b"posix-rename\0" as *const u8 as *const libc::c_char,
                ext_name: b"posix-rename@openssh.com\0" as *const u8 as *const libc::c_char,
                type_0: 0 as libc::c_int as u_int,
                handler: Some(
                    process_extended_posix_rename as unsafe extern "C" fn(u_int32_t) -> (),
                ),
                does_write: 1 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"statvfs\0" as *const u8 as *const libc::c_char,
                ext_name: b"statvfs@openssh.com\0" as *const u8 as *const libc::c_char,
                type_0: 0 as libc::c_int as u_int,
                handler: Some(process_extended_statvfs as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"fstatvfs\0" as *const u8 as *const libc::c_char,
                ext_name: b"fstatvfs@openssh.com\0" as *const u8 as *const libc::c_char,
                type_0: 0 as libc::c_int as u_int,
                handler: Some(process_extended_fstatvfs as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"hardlink\0" as *const u8 as *const libc::c_char,
                ext_name: b"hardlink@openssh.com\0" as *const u8 as *const libc::c_char,
                type_0: 0 as libc::c_int as u_int,
                handler: Some(process_extended_hardlink as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 1 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"fsync\0" as *const u8 as *const libc::c_char,
                ext_name: b"fsync@openssh.com\0" as *const u8 as *const libc::c_char,
                type_0: 0 as libc::c_int as u_int,
                handler: Some(process_extended_fsync as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 1 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"lsetstat\0" as *const u8 as *const libc::c_char,
                ext_name: b"lsetstat@openssh.com\0" as *const u8 as *const libc::c_char,
                type_0: 0 as libc::c_int as u_int,
                handler: Some(process_extended_lsetstat as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 1 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"limits\0" as *const u8 as *const libc::c_char,
                ext_name: b"limits@openssh.com\0" as *const u8 as *const libc::c_char,
                type_0: 0 as libc::c_int as u_int,
                handler: Some(process_extended_limits as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"expand-path\0" as *const u8 as *const libc::c_char,
                ext_name: b"expand-path@openssh.com\0" as *const u8 as *const libc::c_char,
                type_0: 0 as libc::c_int as u_int,
                handler: Some(process_extended_expand as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"copy-data\0" as *const u8 as *const libc::c_char,
                ext_name: b"copy-data\0" as *const u8 as *const libc::c_char,
                type_0: 0 as libc::c_int as u_int,
                handler: Some(process_extended_copy_data as unsafe extern "C" fn(u_int32_t) -> ()),
                does_write: 1 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"home-directory\0" as *const u8 as *const libc::c_char,
                ext_name: b"home-directory\0" as *const u8 as *const libc::c_char,
                type_0: 0 as libc::c_int as u_int,
                handler: Some(
                    process_extended_home_directory as unsafe extern "C" fn(u_int32_t) -> (),
                ),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: b"users-groups-by-id\0" as *const u8 as *const libc::c_char,
                ext_name: b"users-groups-by-id@openssh.com\0" as *const u8 as *const libc::c_char,
                type_0: 0 as libc::c_int as u_int,
                handler: Some(
                    process_extended_get_users_groups_by_id
                        as unsafe extern "C" fn(u_int32_t) -> (),
                ),
                does_write: 0 as libc::c_int,
            };
            init
        },
        {
            let mut init = sftp_handler {
                name: 0 as *const libc::c_char,
                ext_name: 0 as *const libc::c_char,
                type_0: 0 as libc::c_int as u_int,
                handler: None,
                does_write: 0 as libc::c_int,
            };
            init
        },
    ]
};
unsafe extern "C" fn extended_handler_byname(mut name: *const libc::c_char) -> *const sftp_handler {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while (extended_handlers[i as usize].handler).is_some() {
        if libc::strcmp(name, extended_handlers[i as usize].ext_name) == 0 as libc::c_int {
            return &*extended_handlers.as_ptr().offset(i as isize) as *const sftp_handler;
        }
        i += 1;
        i;
    }
    return 0 as *const sftp_handler;
}
unsafe extern "C" fn request_permitted(mut h: *const sftp_handler) -> libc::c_int {
    let mut result: *mut libc::c_char = 0 as *mut libc::c_char;
    if readonly != 0 && (*h).does_write != 0 {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"request_permitted\0"))
                .as_ptr(),
            198 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"Refusing %s request in read-only mode\0" as *const u8 as *const libc::c_char,
            (*h).name,
        );
        return 0 as libc::c_int;
    }
    if !request_denylist.is_null() && {
        result = match_list((*h).name, request_denylist, 0 as *mut u_int);
        !result.is_null()
    } {
        libc::free(result as *mut libc::c_void);
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"request_permitted\0"))
                .as_ptr(),
            204 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"Refusing denylisted %s request\0" as *const u8 as *const libc::c_char,
            (*h).name,
        );
        return 0 as libc::c_int;
    }
    if !request_allowlist.is_null() && {
        result = match_list((*h).name, request_allowlist, 0 as *mut u_int);
        !result.is_null()
    } {
        libc::free(result as *mut libc::c_void);
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"request_permitted\0"))
                .as_ptr(),
            210 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"Permitting allowlisted %s request\0" as *const u8 as *const libc::c_char,
            (*h).name,
        );
        return 1 as libc::c_int;
    }
    if !request_allowlist.is_null() {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"request_permitted\0"))
                .as_ptr(),
            214 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"Refusing non-allowlisted %s request\0" as *const u8 as *const libc::c_char,
            (*h).name,
        );
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn errno_to_portable(mut unixerrno: libc::c_int) -> libc::c_int {
    let mut ret: libc::c_int = 0 as libc::c_int;
    match unixerrno {
        0 => {
            ret = 0 as libc::c_int;
        }
        2 | 20 | 9 | 40 => {
            ret = 2 as libc::c_int;
        }
        1 | 13 | 14 => {
            ret = 3 as libc::c_int;
        }
        36 | 22 => {
            ret = 5 as libc::c_int;
        }
        38 => {
            ret = 8 as libc::c_int;
        }
        _ => {
            ret = 4 as libc::c_int;
        }
    }
    return ret;
}
unsafe extern "C" fn flags_from_portable(mut pflags: libc::c_int) -> libc::c_int {
    let mut flags: libc::c_int = 0 as libc::c_int;
    if pflags & 0x1 as libc::c_int != 0 && pflags & 0x2 as libc::c_int != 0 {
        flags = 0o2 as libc::c_int;
    } else if pflags & 0x1 as libc::c_int != 0 {
        flags = 0 as libc::c_int;
    } else if pflags & 0x2 as libc::c_int != 0 {
        flags = 0o1 as libc::c_int;
    }
    if pflags & 0x4 as libc::c_int != 0 {
        flags |= 0o2000 as libc::c_int;
    }
    if pflags & 0x8 as libc::c_int != 0 {
        flags |= 0o100 as libc::c_int;
    }
    if pflags & 0x10 as libc::c_int != 0 {
        flags |= 0o1000 as libc::c_int;
    }
    if pflags & 0x20 as libc::c_int != 0 {
        flags |= 0o200 as libc::c_int;
    }
    return flags;
}
unsafe extern "C" fn string_from_portable(mut pflags: libc::c_int) -> *const libc::c_char {
    static mut ret: [libc::c_char; 128] = [0; 128];
    *ret.as_mut_ptr() = '\0' as i32 as libc::c_char;
    if pflags & 0x1 as libc::c_int != 0 {
        if *ret.as_mut_ptr() as libc::c_int != '\0' as i32 {
            strlcat(
                ret.as_mut_ptr(),
                b",\0" as *const u8 as *const libc::c_char,
                ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            );
        }
        strlcat(
            ret.as_mut_ptr(),
            b"READ\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
        );
    }
    if pflags & 0x2 as libc::c_int != 0 {
        if *ret.as_mut_ptr() as libc::c_int != '\0' as i32 {
            strlcat(
                ret.as_mut_ptr(),
                b",\0" as *const u8 as *const libc::c_char,
                ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            );
        }
        strlcat(
            ret.as_mut_ptr(),
            b"WRITE\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
        );
    }
    if pflags & 0x4 as libc::c_int != 0 {
        if *ret.as_mut_ptr() as libc::c_int != '\0' as i32 {
            strlcat(
                ret.as_mut_ptr(),
                b",\0" as *const u8 as *const libc::c_char,
                ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            );
        }
        strlcat(
            ret.as_mut_ptr(),
            b"APPEND\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
        );
    }
    if pflags & 0x8 as libc::c_int != 0 {
        if *ret.as_mut_ptr() as libc::c_int != '\0' as i32 {
            strlcat(
                ret.as_mut_ptr(),
                b",\0" as *const u8 as *const libc::c_char,
                ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            );
        }
        strlcat(
            ret.as_mut_ptr(),
            b"CREATE\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
        );
    }
    if pflags & 0x10 as libc::c_int != 0 {
        if *ret.as_mut_ptr() as libc::c_int != '\0' as i32 {
            strlcat(
                ret.as_mut_ptr(),
                b",\0" as *const u8 as *const libc::c_char,
                ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            );
        }
        strlcat(
            ret.as_mut_ptr(),
            b"TRUNCATE\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
        );
    }
    if pflags & 0x20 as libc::c_int != 0 {
        if *ret.as_mut_ptr() as libc::c_int != '\0' as i32 {
            strlcat(
                ret.as_mut_ptr(),
                b",\0" as *const u8 as *const libc::c_char,
                ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
            );
        }
        strlcat(
            ret.as_mut_ptr(),
            b"EXCL\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 128]>() as libc::c_ulong,
        );
    }
    return ret.as_mut_ptr();
}
static mut handles: *mut Handle = 0 as *const Handle as *mut Handle;
static mut num_handles: u_int = 0 as libc::c_int as u_int;
static mut first_unused_handle: libc::c_int = -(1 as libc::c_int);
unsafe extern "C" fn handle_unused(mut i: libc::c_int) {
    (*handles.offset(i as isize)).use_0 = HANDLE_UNUSED as libc::c_int;
    (*handles.offset(i as isize)).next_unused = first_unused_handle;
    first_unused_handle = i;
}
unsafe extern "C" fn handle_new(
    mut use_0: libc::c_int,
    mut name: *const libc::c_char,
    mut fd: libc::c_int,
    mut flags: libc::c_int,
    mut dirp: *mut libc::DIR,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    if first_unused_handle == -(1 as libc::c_int) {
        if num_handles.wrapping_add(1 as libc::c_int as libc::c_uint) <= num_handles {
            return -(1 as libc::c_int);
        }
        num_handles = num_handles.wrapping_add(1);
        num_handles;
        handles = xreallocarray(
            handles as *mut libc::c_void,
            num_handles as size_t,
            ::core::mem::size_of::<Handle>() as libc::c_ulong,
        ) as *mut Handle;
        handle_unused(num_handles.wrapping_sub(1 as libc::c_int as libc::c_uint) as libc::c_int);
    }
    i = first_unused_handle;
    first_unused_handle = (*handles.offset(i as isize)).next_unused;
    (*handles.offset(i as isize)).use_0 = use_0;
    let ref mut fresh0 = (*handles.offset(i as isize)).dirp;
    *fresh0 = dirp;
    (*handles.offset(i as isize)).fd = fd;
    (*handles.offset(i as isize)).flags = flags;
    let ref mut fresh1 = (*handles.offset(i as isize)).name;
    *fresh1 = crate::xmalloc::xstrdup(name);
    let ref mut fresh2 = (*handles.offset(i as isize)).bytes_write;
    *fresh2 = 0 as libc::c_int as u_int64_t;
    (*handles.offset(i as isize)).bytes_read = *fresh2;
    return i;
}
unsafe extern "C" fn handle_is_ok(mut i: libc::c_int, mut type_0: libc::c_int) -> libc::c_int {
    return (i >= 0 as libc::c_int
        && (i as u_int) < num_handles
        && (*handles.offset(i as isize)).use_0 == type_0) as libc::c_int;
}
unsafe extern "C" fn handle_to_string(
    mut handle: libc::c_int,
    mut stringp: *mut *mut u_char,
    mut hlenp: *mut libc::c_int,
) -> libc::c_int {
    if stringp.is_null() || hlenp.is_null() {
        return -(1 as libc::c_int);
    }
    *stringp =
        crate::xmalloc::xmalloc(::core::mem::size_of::<int32_t>() as libc::c_ulong) as *mut u_char;
    put_u32(*stringp as *mut libc::c_void, handle as u_int32_t);
    *hlenp = ::core::mem::size_of::<int32_t>() as libc::c_ulong as libc::c_int;
    return 0 as libc::c_int;
}
unsafe extern "C" fn handle_from_string(mut handle: *const u_char, mut hlen: u_int) -> libc::c_int {
    let mut val: libc::c_int = 0;
    if hlen as libc::c_ulong != ::core::mem::size_of::<int32_t>() as libc::c_ulong {
        return -(1 as libc::c_int);
    }
    val = get_u32(handle as *const libc::c_void) as libc::c_int;
    if handle_is_ok(val, HANDLE_FILE as libc::c_int) != 0
        || handle_is_ok(val, HANDLE_DIR as libc::c_int) != 0
    {
        return val;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn handle_to_name(mut handle: libc::c_int) -> *mut libc::c_char {
    if handle_is_ok(handle, HANDLE_DIR as libc::c_int) != 0
        || handle_is_ok(handle, HANDLE_FILE as libc::c_int) != 0
    {
        return (*handles.offset(handle as isize)).name;
    }
    return 0 as *mut libc::c_char;
}
unsafe extern "C" fn handle_to_dir(mut handle: libc::c_int) -> *mut libc::DIR {
    if handle_is_ok(handle, HANDLE_DIR as libc::c_int) != 0 {
        return (*handles.offset(handle as isize)).dirp;
    }
    return 0 as *mut libc::DIR;
}
unsafe extern "C" fn handle_to_fd(mut handle: libc::c_int) -> libc::c_int {
    if handle_is_ok(handle, HANDLE_FILE as libc::c_int) != 0 {
        return (*handles.offset(handle as isize)).fd;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn handle_to_flags(mut handle: libc::c_int) -> libc::c_int {
    if handle_is_ok(handle, HANDLE_FILE as libc::c_int) != 0 {
        return (*handles.offset(handle as isize)).flags;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn handle_update_read(mut handle: libc::c_int, mut bytes: ssize_t) {
    if handle_is_ok(handle, HANDLE_FILE as libc::c_int) != 0
        && bytes > 0 as libc::c_int as libc::c_long
    {
        let ref mut fresh3 = (*handles.offset(handle as isize)).bytes_read;
        *fresh3 = (*fresh3 as libc::c_ulong).wrapping_add(bytes as libc::c_ulong) as u_int64_t
            as u_int64_t;
    }
}
unsafe extern "C" fn handle_update_write(mut handle: libc::c_int, mut bytes: ssize_t) {
    if handle_is_ok(handle, HANDLE_FILE as libc::c_int) != 0
        && bytes > 0 as libc::c_int as libc::c_long
    {
        let ref mut fresh4 = (*handles.offset(handle as isize)).bytes_write;
        *fresh4 = (*fresh4 as libc::c_ulong).wrapping_add(bytes as libc::c_ulong) as u_int64_t
            as u_int64_t;
    }
}
unsafe extern "C" fn handle_bytes_read(mut handle: libc::c_int) -> u_int64_t {
    if handle_is_ok(handle, HANDLE_FILE as libc::c_int) != 0 {
        return (*handles.offset(handle as isize)).bytes_read;
    }
    return 0 as libc::c_int as u_int64_t;
}
unsafe extern "C" fn handle_bytes_write(mut handle: libc::c_int) -> u_int64_t {
    if handle_is_ok(handle, HANDLE_FILE as libc::c_int) != 0 {
        return (*handles.offset(handle as isize)).bytes_write;
    }
    return 0 as libc::c_int as u_int64_t;
}
unsafe extern "C" fn handle_close(mut handle: libc::c_int) -> libc::c_int {
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if handle_is_ok(handle, HANDLE_FILE as libc::c_int) != 0 {
        ret = close((*handles.offset(handle as isize)).fd);
        libc::free((*handles.offset(handle as isize)).name as *mut libc::c_void);
        handle_unused(handle);
    } else if handle_is_ok(handle, HANDLE_DIR as libc::c_int) != 0 {
        ret = libc::closedir((*handles.offset(handle as isize)).dirp);
        libc::free((*handles.offset(handle as isize)).name as *mut libc::c_void);
        handle_unused(handle);
    } else {
        *libc::__errno_location() = 2 as libc::c_int;
    }
    return ret;
}
unsafe extern "C" fn handle_log_close(mut handle: libc::c_int, mut emsg: *mut libc::c_char) {
    if handle_is_ok(handle, HANDLE_FILE as libc::c_int) != 0 {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"handle_log_close\0"))
                .as_ptr(),
            484 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%s%sclose \"%s\" bytes read %llu written %llu\0" as *const u8 as *const libc::c_char,
            if emsg.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                emsg as *const libc::c_char
            },
            if emsg.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b" \0" as *const u8 as *const libc::c_char
            },
            handle_to_name(handle),
            handle_bytes_read(handle) as libc::c_ulonglong,
            handle_bytes_write(handle) as libc::c_ulonglong,
        );
    } else {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"handle_log_close\0"))
                .as_ptr(),
            488 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%s%sclosedir \"%s\"\0" as *const u8 as *const libc::c_char,
            if emsg.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                emsg as *const libc::c_char
            },
            if emsg.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                b" \0" as *const u8 as *const libc::c_char
            },
            handle_to_name(handle),
        );
    };
}
unsafe extern "C" fn handle_log_exit() {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < num_handles {
        if (*handles.offset(i as isize)).use_0 != HANDLE_UNUSED as libc::c_int {
            handle_log_close(
                i as libc::c_int,
                b"forced\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn get_handle(
    mut queue: *mut crate::sshbuf::sshbuf,
    mut hp: *mut libc::c_int,
) -> libc::c_int {
    let mut handle: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    let mut hlen: size_t = 0;
    *hp = -(1 as libc::c_int);
    r = sshbuf_get_string(queue, &mut handle, &mut hlen);
    if r != 0 as libc::c_int {
        return r;
    }
    if hlen < 256 as libc::c_int as libc::c_ulong {
        *hp = handle_from_string(handle, hlen as u_int);
    }
    libc::free(handle as *mut libc::c_void);
    return 0 as libc::c_int;
}
unsafe extern "C" fn send_msg(mut m: *mut crate::sshbuf::sshbuf) {
    let mut r: libc::c_int = 0;
    r = sshbuf_put_stringb(oqueue, m);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"send_msg\0")).as_ptr(),
            526 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"enqueue\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::sshbuf::sshbuf_reset(m);
}
unsafe extern "C" fn status_to_message(mut status: u_int32_t) -> *const libc::c_char {
    static mut status_messages: [*const libc::c_char; 10] = [
        b"Success\0" as *const u8 as *const libc::c_char,
        b"End of file\0" as *const u8 as *const libc::c_char,
        b"No such file\0" as *const u8 as *const libc::c_char,
        b"Permission denied\0" as *const u8 as *const libc::c_char,
        b"Failure\0" as *const u8 as *const libc::c_char,
        b"Bad message\0" as *const u8 as *const libc::c_char,
        b"No connection\0" as *const u8 as *const libc::c_char,
        b"Connection lost\0" as *const u8 as *const libc::c_char,
        b"Operation unsupported\0" as *const u8 as *const libc::c_char,
        b"Unknown error\0" as *const u8 as *const libc::c_char,
    ];
    return status_messages[(if status < 8 as libc::c_int as libc::c_uint {
        status
    } else {
        8 as libc::c_int as libc::c_uint
    }) as usize];
}
unsafe extern "C" fn send_status_errmsg(
    mut id: u_int32_t,
    mut status: u_int32_t,
    mut errmsg: *const libc::c_char,
) {
    let mut msg: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"send_status_errmsg\0"))
            .as_ptr(),
        554 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: sent status %u\0" as *const u8 as *const libc::c_char,
        id,
        status,
    );
    if log_level as libc::c_int > SYSLOG_LEVEL_VERBOSE as libc::c_int
        || status != 0 as libc::c_int as libc::c_uint && status != 1 as libc::c_int as libc::c_uint
    {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"send_status_errmsg\0"))
                .as_ptr(),
            557 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"sent status %s\0" as *const u8 as *const libc::c_char,
            status_to_message(status),
        );
    }
    msg = crate::sshbuf::sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"send_status_errmsg\0"))
                .as_ptr(),
            559 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_u8(msg, 101 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(msg, status);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"send_status_errmsg\0"))
                .as_ptr(),
            563 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    if version >= 3 as libc::c_int as libc::c_uint {
        r = sshbuf_put_cstring(
            msg,
            if errmsg.is_null() {
                status_to_message(status)
            } else {
                errmsg
            },
        );
        if r != 0 as libc::c_int || {
            r = sshbuf_put_cstring(msg, b"\0" as *const u8 as *const libc::c_char);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"send_status_errmsg\0",
                ))
                .as_ptr(),
                568 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose message\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    send_msg(msg);
    crate::sshbuf::sshbuf_free(msg);
}
unsafe extern "C" fn send_status(mut id: u_int32_t, mut status: u_int32_t) {
    send_status_errmsg(id, status, 0 as *const libc::c_char);
}
unsafe extern "C" fn send_data_or_handle(
    mut type_0: libc::c_char,
    mut id: u_int32_t,
    mut data: *const u_char,
    mut dlen: libc::c_int,
) {
    let mut msg: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    msg = crate::sshbuf::sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"send_data_or_handle\0"))
                .as_ptr(),
            587 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_u8(msg, type_0 as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(msg, data as *const libc::c_void, dlen as size_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"send_data_or_handle\0"))
                .as_ptr(),
            591 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(msg);
    crate::sshbuf::sshbuf_free(msg);
}
unsafe extern "C" fn send_data(mut id: u_int32_t, mut data: *const u_char, mut dlen: libc::c_int) {
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"send_data\0")).as_ptr(),
        599 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: sent data len %d\0" as *const u8 as *const libc::c_char,
        id,
        dlen,
    );
    send_data_or_handle(103 as libc::c_int as libc::c_char, id, data, dlen);
}
unsafe extern "C" fn send_handle(mut id: u_int32_t, mut handle: libc::c_int) {
    let mut string: *mut u_char = 0 as *mut u_char;
    let mut hlen: libc::c_int = 0;
    handle_to_string(handle, &mut string, &mut hlen);
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"send_handle\0")).as_ptr(),
        610 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: sent handle %d\0" as *const u8 as *const libc::c_char,
        id,
        handle,
    );
    send_data_or_handle(102 as libc::c_int as libc::c_char, id, string, hlen);
    libc::free(string as *mut libc::c_void);
}
unsafe extern "C" fn send_names(mut id: u_int32_t, mut count: libc::c_int, mut stats: *const Stat) {
    let mut msg: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    msg = crate::sshbuf::sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"send_names\0")).as_ptr(),
            622 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_u8(msg, 104 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u32(msg, count as u_int32_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"send_names\0")).as_ptr(),
            626 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"send_names\0")).as_ptr(),
        627 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: sent names count %d\0" as *const u8 as *const libc::c_char,
        id,
        count,
    );
    i = 0 as libc::c_int;
    while i < count {
        r = sshbuf_put_cstring(msg, (*stats.offset(i as isize)).name);
        if r != 0 as libc::c_int
            || {
                r = sshbuf_put_cstring(msg, (*stats.offset(i as isize)).long_name);
                r != 0 as libc::c_int
            }
            || {
                r = encode_attrib(msg, &(*stats.offset(i as isize)).attrib);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"send_names\0"))
                    .as_ptr(),
                632 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose filenames/attrib\0" as *const u8 as *const libc::c_char,
            );
        }
        i += 1;
        i;
    }
    send_msg(msg);
    crate::sshbuf::sshbuf_free(msg);
}
unsafe extern "C" fn send_attrib(mut id: u_int32_t, mut a: *const Attrib) {
    let mut msg: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"send_attrib\0")).as_ptr(),
        644 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: sent attrib have 0x%x\0" as *const u8 as *const libc::c_char,
        id,
        (*a).flags,
    );
    msg = crate::sshbuf::sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"send_attrib\0")).as_ptr(),
            646 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_u8(msg, 105 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = encode_attrib(msg, a);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"send_attrib\0")).as_ptr(),
            650 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(msg);
    crate::sshbuf::sshbuf_free(msg);
}
unsafe extern "C" fn send_statvfs(mut id: u_int32_t, mut st: *mut statvfs) {
    let mut msg: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut flag: u_int64_t = 0;
    let mut r: libc::c_int = 0;
    flag = (if (*st).f_flag & ST_RDONLY as libc::c_int as libc::c_ulong != 0 {
        0x1 as libc::c_int
    } else {
        0 as libc::c_int
    }) as u_int64_t;
    flag |= (if (*st).f_flag & ST_NOSUID as libc::c_int as libc::c_ulong != 0 {
        0x2 as libc::c_int
    } else {
        0 as libc::c_int
    }) as libc::c_ulong;
    msg = crate::sshbuf::sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"send_statvfs\0")).as_ptr(),
            666 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_u8(msg, 201 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, (*st).f_bsize);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, (*st).f_frsize);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, (*st).f_blocks);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, (*st).f_bfree);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, (*st).f_bavail);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, (*st).f_files);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, (*st).f_ffree);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, (*st).f_favail);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, (*st).f_fsid);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, flag);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, (*st).f_namemax);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"send_statvfs\0")).as_ptr(),
            680 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(msg);
    crate::sshbuf::sshbuf_free(msg);
}
unsafe extern "C" fn compose_extension(
    mut msg: *mut crate::sshbuf::sshbuf,
    mut name: *const libc::c_char,
    mut ver: *const libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut exthnd: *const sftp_handler = 0 as *const sftp_handler;
    exthnd = extended_handler_byname(name);
    if exthnd.is_null() {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"compose_extension\0"))
                .as_ptr(),
            696 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"internal error: no handler for %s\0" as *const u8 as *const libc::c_char,
            name,
        );
    }
    if request_permitted(exthnd) == 0 {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"compose_extension\0"))
                .as_ptr(),
            698 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"refusing to advertise disallowed extension %s\0" as *const u8 as *const libc::c_char,
            name,
        );
        return 0 as libc::c_int;
    }
    r = sshbuf_put_cstring(msg, name);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_cstring(msg, ver);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"compose_extension\0"))
                .as_ptr(),
            703 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose %s\0" as *const u8 as *const libc::c_char,
            name,
        );
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn process_init() {
    let mut msg: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    r = sshbuf_get_u32(iqueue, &mut version);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_init\0")).as_ptr(),
            716 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_init\0")).as_ptr(),
        717 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_VERBOSE,
        0 as *const libc::c_char,
        b"received client version %u\0" as *const u8 as *const libc::c_char,
        version,
    );
    msg = crate::sshbuf::sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_init\0")).as_ptr(),
            719 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_u8(msg, 2 as libc::c_int as u_char);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_u32(msg, 3 as libc::c_int as u_int32_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_init\0")).as_ptr(),
            722 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    compose_extension(
        msg,
        b"posix-rename@openssh.com\0" as *const u8 as *const libc::c_char,
        b"1\0" as *const u8 as *const libc::c_char,
    );
    compose_extension(
        msg,
        b"statvfs@openssh.com\0" as *const u8 as *const libc::c_char,
        b"2\0" as *const u8 as *const libc::c_char,
    );
    compose_extension(
        msg,
        b"fstatvfs@openssh.com\0" as *const u8 as *const libc::c_char,
        b"2\0" as *const u8 as *const libc::c_char,
    );
    compose_extension(
        msg,
        b"hardlink@openssh.com\0" as *const u8 as *const libc::c_char,
        b"1\0" as *const u8 as *const libc::c_char,
    );
    compose_extension(
        msg,
        b"fsync@openssh.com\0" as *const u8 as *const libc::c_char,
        b"1\0" as *const u8 as *const libc::c_char,
    );
    compose_extension(
        msg,
        b"lsetstat@openssh.com\0" as *const u8 as *const libc::c_char,
        b"1\0" as *const u8 as *const libc::c_char,
    );
    compose_extension(
        msg,
        b"limits@openssh.com\0" as *const u8 as *const libc::c_char,
        b"1\0" as *const u8 as *const libc::c_char,
    );
    compose_extension(
        msg,
        b"expand-path@openssh.com\0" as *const u8 as *const libc::c_char,
        b"1\0" as *const u8 as *const libc::c_char,
    );
    compose_extension(
        msg,
        b"copy-data\0" as *const u8 as *const libc::c_char,
        b"1\0" as *const u8 as *const libc::c_char,
    );
    compose_extension(
        msg,
        b"home-directory\0" as *const u8 as *const libc::c_char,
        b"1\0" as *const u8 as *const libc::c_char,
    );
    compose_extension(
        msg,
        b"users-groups-by-id@openssh.com\0" as *const u8 as *const libc::c_char,
        b"1\0" as *const u8 as *const libc::c_char,
    );
    send_msg(msg);
    crate::sshbuf::sshbuf_free(msg);
}
unsafe extern "C" fn process_open(mut id: u_int32_t) {
    let mut pflags: u_int32_t = 0;
    let mut a: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut handle: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut flags: libc::c_int = 0;
    let mut mode: libc::c_int = 0;
    let mut status: libc::c_int = 4 as libc::c_int;
    r = sshbuf_get_cstring(iqueue, &mut name, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_u32(iqueue, &mut pflags);
            r != 0 as libc::c_int
        }
        || {
            r = decode_attrib(iqueue, &mut a);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_open\0")).as_ptr(),
            752 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_open\0")).as_ptr(),
        754 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: open flags %d\0" as *const u8 as *const libc::c_char,
        id,
        pflags,
    );
    flags = flags_from_portable(pflags as libc::c_int);
    mode = (if a.flags & 0x4 as libc::c_int as libc::c_uint != 0 {
        a.perm
    } else {
        0o666 as libc::c_int as libc::c_uint
    }) as libc::c_int;
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_open\0")).as_ptr(),
        758 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"open \"%s\" flags %s mode 0%o\0" as *const u8 as *const libc::c_char,
        name,
        string_from_portable(pflags as libc::c_int),
        mode,
    );
    if readonly != 0
        && (flags & 0o3 as libc::c_int != 0 as libc::c_int
            || flags & (0o100 as libc::c_int | 0o1000 as libc::c_int) != 0 as libc::c_int)
    {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_open\0")).as_ptr(),
            762 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"Refusing open request in read-only mode\0" as *const u8 as *const libc::c_char,
        );
        status = 3 as libc::c_int;
    } else {
        fd = libc::open(name, flags, mode);
        if fd == -(1 as libc::c_int) {
            status = errno_to_portable(*libc::__errno_location());
        } else {
            handle = handle_new(
                HANDLE_FILE as libc::c_int,
                name,
                fd,
                flags,
                0 as *mut libc::DIR,
            );
            if handle < 0 as libc::c_int {
                close(fd);
            } else {
                send_handle(id, handle);
                status = 0 as libc::c_int;
            }
        }
    }
    if status != 0 as libc::c_int {
        send_status(id, status as u_int32_t);
    }
    libc::free(name as *mut libc::c_void);
}
unsafe extern "C" fn process_close(mut id: u_int32_t) {
    let mut r: libc::c_int = 0;
    let mut handle: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut status: libc::c_int = 4 as libc::c_int;
    r = get_handle(iqueue, &mut handle);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_close\0"))
                .as_ptr(),
            789 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_close\0")).as_ptr(),
        791 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: close handle %u\0" as *const u8 as *const libc::c_char,
        id,
        handle,
    );
    handle_log_close(handle, 0 as *mut libc::c_char);
    ret = handle_close(handle);
    status = if ret == -(1 as libc::c_int) {
        errno_to_portable(*libc::__errno_location())
    } else {
        0 as libc::c_int
    };
    send_status(id, status as u_int32_t);
}
unsafe extern "C" fn process_read(mut id: u_int32_t) {
    let mut current_block: u64;
    static mut buf: *mut u_char = 0 as *const u_char as *mut u_char;
    static mut buflen: size_t = 0;
    let mut len: u_int32_t = 0;
    let mut r: libc::c_int = 0;
    let mut handle: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut status: libc::c_int = 4 as libc::c_int;
    let mut off: u_int64_t = 0;
    r = get_handle(iqueue, &mut handle);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_u64(iqueue, &mut off);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(iqueue, &mut len);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_read\0")).as_ptr(),
            810 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_read\0")).as_ptr(),
        813 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: read \"%s\" (handle %d) off %llu len %u\0" as *const u8
            as *const libc::c_char,
        id,
        handle_to_name(handle),
        handle,
        off as libc::c_ulonglong,
        len,
    );
    fd = handle_to_fd(handle);
    if !(fd == -(1 as libc::c_int)) {
        if len > (256 as libc::c_int * 1024 as libc::c_int - 1024 as libc::c_int) as libc::c_uint {
            crate::log::sshlog(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_read\0"))
                    .as_ptr(),
                817 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"read change len %u to %u\0" as *const u8 as *const libc::c_char,
                len,
                256 as libc::c_int * 1024 as libc::c_int - 1024 as libc::c_int,
            );
            len = (256 as libc::c_int * 1024 as libc::c_int - 1024 as libc::c_int) as u_int32_t;
        }
        if len as libc::c_ulong > buflen {
            crate::log::sshlog(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_read\0"))
                    .as_ptr(),
                821 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"allocate %zu => %u\0" as *const u8 as *const libc::c_char,
                buflen,
                len,
            );
            buf = realloc(buf as *mut libc::c_void, len as libc::c_ulong) as *mut u_char;
            if buf.is_null() {
                sshfatal(
                    b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_read\0"))
                        .as_ptr(),
                    823 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"realloc failed\0" as *const u8 as *const libc::c_char,
                );
            }
            buflen = len as size_t;
        }
        if lseek(fd, off as __off_t, 0 as libc::c_int) == -(1 as libc::c_int) as libc::c_long {
            status = errno_to_portable(*libc::__errno_location());
            crate::log::sshlog(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_read\0"))
                    .as_ptr(),
                829 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"seek \"%.100s\": %s\0" as *const u8 as *const libc::c_char,
                handle_to_name(handle),
                libc::strerror(*libc::__errno_location()),
            );
        } else {
            if len == 0 as libc::c_int as libc::c_uint {
                ret = 0 as libc::c_int;
                current_block = 2668756484064249700;
            } else {
                ret = read(fd, buf as *mut libc::c_void, len as size_t) as libc::c_int;
                if ret == -(1 as libc::c_int) {
                    status = errno_to_portable(*libc::__errno_location());
                    crate::log::sshlog(
                        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"process_read\0",
                        ))
                        .as_ptr(),
                        838 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"read \"%.100s\": %s\0" as *const u8 as *const libc::c_char,
                        handle_to_name(handle),
                        libc::strerror(*libc::__errno_location()),
                    );
                    current_block = 7767887306780309995;
                } else if ret == 0 as libc::c_int {
                    status = 1 as libc::c_int;
                    current_block = 7767887306780309995;
                } else {
                    current_block = 2668756484064249700;
                }
            }
            match current_block {
                7767887306780309995 => {}
                _ => {
                    send_data(id, buf, ret);
                    handle_update_read(handle, ret as ssize_t);
                    status = 0 as libc::c_int;
                }
            }
        }
    }
    if status != 0 as libc::c_int {
        send_status(id, status as u_int32_t);
    }
}
unsafe extern "C" fn process_write(mut id: u_int32_t) {
    let mut off: u_int64_t = 0;
    let mut len: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut handle: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut status: libc::c_int = 0;
    let mut data: *mut u_char = 0 as *mut u_char;
    r = get_handle(iqueue, &mut handle);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_u64(iqueue, &mut off);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_string(iqueue, &mut data, &mut len);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_write\0"))
                .as_ptr(),
            864 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_write\0")).as_ptr(),
        867 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: write \"%s\" (handle %d) off %llu len %zu\0" as *const u8
            as *const libc::c_char,
        id,
        handle_to_name(handle),
        handle,
        off as libc::c_ulonglong,
        len,
    );
    fd = handle_to_fd(handle);
    if fd < 0 as libc::c_int {
        status = 4 as libc::c_int;
    } else if handle_to_flags(handle) & 0o2000 as libc::c_int == 0
        && lseek(fd, off as __off_t, 0 as libc::c_int) == -(1 as libc::c_int) as libc::c_long
    {
        status = errno_to_portable(*libc::__errno_location());
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_write\0"))
                .as_ptr(),
            877 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"seek \"%.100s\": %s\0" as *const u8 as *const libc::c_char,
            handle_to_name(handle),
            libc::strerror(*libc::__errno_location()),
        );
    } else {
        ret = write(fd, data as *const libc::c_void, len) as libc::c_int;
        if ret == -(1 as libc::c_int) {
            status = errno_to_portable(*libc::__errno_location());
            crate::log::sshlog(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_write\0"))
                    .as_ptr(),
                884 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"write \"%.100s\": %s\0" as *const u8 as *const libc::c_char,
                handle_to_name(handle),
                libc::strerror(*libc::__errno_location()),
            );
        } else if ret as size_t == len {
            status = 0 as libc::c_int;
            handle_update_write(handle, ret as ssize_t);
        } else {
            crate::log::sshlog(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_write\0"))
                    .as_ptr(),
                889 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"nothing at all written\0" as *const u8 as *const libc::c_char,
            );
            status = 4 as libc::c_int;
        }
    }
    send_status(id, status as u_int32_t);
    libc::free(data as *mut libc::c_void);
}
unsafe extern "C" fn process_do_stat(mut id: u_int32_t, mut do_lstat: libc::c_int) {
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
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 4 as libc::c_int;
    r = sshbuf_get_cstring(iqueue, &mut name, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_do_stat\0"))
                .as_ptr(),
            907 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_do_stat\0")).as_ptr(),
        909 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: %sstat\0" as *const u8 as *const libc::c_char,
        id,
        if do_lstat != 0 {
            b"l\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_do_stat\0")).as_ptr(),
        910 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_VERBOSE,
        0 as *const libc::c_char,
        b"%sstat name \"%s\"\0" as *const u8 as *const libc::c_char,
        if do_lstat != 0 {
            b"l\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        name,
    );
    r = if do_lstat != 0 {
        lstat(name, &mut st)
    } else {
        libc::stat(name, &mut st)
    };
    if r == -(1 as libc::c_int) {
        status = errno_to_portable(*libc::__errno_location());
    } else {
        stat_to_attrib(&mut st, &mut a);
        send_attrib(id, &mut a);
        status = 0 as libc::c_int;
    }
    if status != 0 as libc::c_int {
        send_status(id, status as u_int32_t);
    }
    libc::free(name as *mut libc::c_void);
}
unsafe extern "C" fn process_stat(mut id: u_int32_t) {
    process_do_stat(id, 0 as libc::c_int);
}
unsafe extern "C" fn process_lstat(mut id: u_int32_t) {
    process_do_stat(id, 1 as libc::c_int);
}
unsafe extern "C" fn process_fstat(mut id: u_int32_t) {
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
    let mut fd: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut handle: libc::c_int = 0;
    let mut status: libc::c_int = 4 as libc::c_int;
    r = get_handle(iqueue, &mut handle);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_fstat\0"))
                .as_ptr(),
            944 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_fstat\0")).as_ptr(),
        946 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: libc::fstat \"%s\" (handle %u)\0" as *const u8 as *const libc::c_char,
        id,
        handle_to_name(handle),
        handle,
    );
    fd = handle_to_fd(handle);
    if fd >= 0 as libc::c_int {
        r = libc::fstat(fd, &mut st);
        if r == -(1 as libc::c_int) {
            status = errno_to_portable(*libc::__errno_location());
        } else {
            stat_to_attrib(&mut st, &mut a);
            send_attrib(id, &mut a);
            status = 0 as libc::c_int;
        }
    }
    if status != 0 as libc::c_int {
        send_status(id, status as u_int32_t);
    }
}
unsafe extern "C" fn attrib_to_tv(mut a: *const Attrib) -> *mut libc::timeval {
    static mut tv: [libc::timeval; 2] = [libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    }; 2];
    tv[0 as libc::c_int as usize].tv_sec = (*a).atime as __time_t;
    tv[0 as libc::c_int as usize].tv_usec = 0 as libc::c_int as __suseconds_t;
    tv[1 as libc::c_int as usize].tv_sec = (*a).mtime as __time_t;
    tv[1 as libc::c_int as usize].tv_usec = 0 as libc::c_int as __suseconds_t;
    return tv.as_mut_ptr();
}
unsafe extern "C" fn attrib_to_ts(mut a: *const Attrib) -> *mut libc::timespec {
    static mut ts: [libc::timespec; 2] = [libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    }; 2];
    ts[0 as libc::c_int as usize].tv_sec = (*a).atime as __time_t;
    ts[0 as libc::c_int as usize].tv_nsec = 0 as libc::c_int as __syscall_slong_t;
    ts[1 as libc::c_int as usize].tv_sec = (*a).mtime as __time_t;
    ts[1 as libc::c_int as usize].tv_nsec = 0 as libc::c_int as __syscall_slong_t;
    return ts.as_mut_ptr();
}
unsafe extern "C" fn process_setstat(mut id: u_int32_t) {
    let mut a: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 0 as libc::c_int;
    r = sshbuf_get_cstring(iqueue, &mut name, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = decode_attrib(iqueue, &mut a);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_setstat\0"))
                .as_ptr(),
            995 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_setstat\0")).as_ptr(),
        997 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: setstat name \"%s\"\0" as *const u8 as *const libc::c_char,
        id,
        name,
    );
    if a.flags & 0x1 as libc::c_int as libc::c_uint != 0 {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_setstat\0"))
                .as_ptr(),
            1000 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"set \"%s\" size %llu\0" as *const u8 as *const libc::c_char,
            name,
            a.size as libc::c_ulonglong,
        );
        r = truncate(name, a.size as __off_t);
        if r == -(1 as libc::c_int) {
            status = errno_to_portable(*libc::__errno_location());
        }
    }
    if a.flags & 0x4 as libc::c_int as libc::c_uint != 0 {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_setstat\0"))
                .as_ptr(),
            1006 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"set \"%s\" mode %04o\0" as *const u8 as *const libc::c_char,
            name,
            a.perm,
        );
        r = libc::chmod(name, a.perm & 0o7777 as libc::c_int as libc::c_uint);
        if r == -(1 as libc::c_int) {
            status = errno_to_portable(*libc::__errno_location());
        }
    }
    if a.flags & 0x8 as libc::c_int as libc::c_uint != 0 {
        let mut buf: [libc::c_char; 64] = [0; 64];
        let mut t: time_t = a.mtime as time_t;
        strftime(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
            b"%Y%m%d-%H:%M:%S\0" as *const u8 as *const libc::c_char,
            localtime(&mut t),
        );
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_setstat\0"))
                .as_ptr(),
            1017 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"set \"%s\" modtime %s\0" as *const u8 as *const libc::c_char,
            name,
            buf.as_mut_ptr(),
        );
        r = libc::utimes(name, attrib_to_tv(&mut a) as *const libc::timeval);
        if r == -(1 as libc::c_int) {
            status = errno_to_portable(*libc::__errno_location());
        }
    }
    if a.flags & 0x2 as libc::c_int as libc::c_uint != 0 {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_setstat\0"))
                .as_ptr(),
            1024 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"set \"%s\" owner %lu group %lu\0" as *const u8 as *const libc::c_char,
            name,
            a.uid as u_long,
            a.gid as u_long,
        );
        r = chown(name, a.uid, a.gid);
        if r == -(1 as libc::c_int) {
            status = errno_to_portable(*libc::__errno_location());
        }
    }
    send_status(id, status as u_int32_t);
    libc::free(name as *mut libc::c_void);
}
unsafe extern "C" fn process_fsetstat(mut id: u_int32_t) {
    let mut a: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    let mut handle: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 0 as libc::c_int;
    r = get_handle(iqueue, &mut handle);
    if r != 0 as libc::c_int || {
        r = decode_attrib(iqueue, &mut a);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_fsetstat\0"))
                .as_ptr(),
            1042 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_fsetstat\0")).as_ptr(),
        1044 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: fsetstat handle %d\0" as *const u8 as *const libc::c_char,
        id,
        handle,
    );
    fd = handle_to_fd(handle);
    if fd < 0 as libc::c_int {
        status = 4 as libc::c_int;
    } else {
        let mut name: *mut libc::c_char = handle_to_name(handle);
        if a.flags & 0x1 as libc::c_int as libc::c_uint != 0 {
            crate::log::sshlog(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_fsetstat\0"))
                    .as_ptr(),
                1053 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"set \"%s\" size %llu\0" as *const u8 as *const libc::c_char,
                name,
                a.size as libc::c_ulonglong,
            );
            r = libc::ftruncate(fd, a.size as __off_t);
            if r == -(1 as libc::c_int) {
                status = errno_to_portable(*libc::__errno_location());
            }
        }
        if a.flags & 0x4 as libc::c_int as libc::c_uint != 0 {
            crate::log::sshlog(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_fsetstat\0"))
                    .as_ptr(),
                1059 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"set \"%s\" mode %04o\0" as *const u8 as *const libc::c_char,
                name,
                a.perm,
            );
            r = libc::fchmod(fd, a.perm & 0o7777 as libc::c_int as libc::c_uint);
            if r == -(1 as libc::c_int) {
                status = errno_to_portable(*libc::__errno_location());
            }
        }
        if a.flags & 0x8 as libc::c_int as libc::c_uint != 0 {
            let mut buf: [libc::c_char; 64] = [0; 64];
            let mut t: time_t = a.mtime as time_t;
            strftime(
                buf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
                b"%Y%m%d-%H:%M:%S\0" as *const u8 as *const libc::c_char,
                localtime(&mut t),
            );
            crate::log::sshlog(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_fsetstat\0"))
                    .as_ptr(),
                1074 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"set \"%s\" modtime %s\0" as *const u8 as *const libc::c_char,
                name,
                buf.as_mut_ptr(),
            );
            r = futimes(fd, attrib_to_tv(&mut a) as *const libc::timeval);
            if r == -(1 as libc::c_int) {
                status = errno_to_portable(*libc::__errno_location());
            }
        }
        if a.flags & 0x2 as libc::c_int as libc::c_uint != 0 {
            crate::log::sshlog(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_fsetstat\0"))
                    .as_ptr(),
                1085 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"set \"%s\" owner %lu group %lu\0" as *const u8 as *const libc::c_char,
                name,
                a.uid as u_long,
                a.gid as u_long,
            );
            r = fchown(fd, a.uid, a.gid);
            if r == -(1 as libc::c_int) {
                status = errno_to_portable(*libc::__errno_location());
            }
        }
    }
    send_status(id, status as u_int32_t);
}
unsafe extern "C" fn process_opendir(mut id: u_int32_t) {
    let mut dirp: *mut libc::DIR = 0 as *mut libc::DIR;
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut handle: libc::c_int = 0;
    let mut status: libc::c_int = 4 as libc::c_int;
    r = sshbuf_get_cstring(iqueue, &mut path, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_opendir\0"))
                .as_ptr(),
            1106 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_opendir\0")).as_ptr(),
        1108 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: libc::opendir\0" as *const u8 as *const libc::c_char,
        id,
    );
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_opendir\0")).as_ptr(),
        1109 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"libc::opendir \"%s\"\0" as *const u8 as *const libc::c_char,
        path,
    );
    dirp = libc::opendir(path);
    if dirp.is_null() {
        status = errno_to_portable(*libc::__errno_location());
    } else {
        handle = handle_new(
            HANDLE_DIR as libc::c_int,
            path,
            0 as libc::c_int,
            0 as libc::c_int,
            dirp,
        );
        if handle < 0 as libc::c_int {
            libc::closedir(dirp);
        } else {
            send_handle(id, handle);
            status = 0 as libc::c_int;
        }
    }
    if status != 0 as libc::c_int {
        send_status(id, status as u_int32_t);
    }
    libc::free(path as *mut libc::c_void);
}
unsafe extern "C" fn process_readdir(mut id: u_int32_t) {
    let mut dirp: *mut libc::DIR = 0 as *mut libc::DIR;
    let mut dp: *mut libc::dirent = 0 as *mut libc::dirent;
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut handle: libc::c_int = 0;
    r = get_handle(iqueue, &mut handle);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_readdir\0"))
                .as_ptr(),
            1137 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_readdir\0")).as_ptr(),
        1140 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: libc::readdir \"%s\" (handle %d)\0" as *const u8 as *const libc::c_char,
        id,
        handle_to_name(handle),
        handle,
    );
    dirp = handle_to_dir(handle);
    path = handle_to_name(handle);
    if dirp.is_null() || path.is_null() {
        send_status(id, 4 as libc::c_int as u_int32_t);
    } else {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let mut pathname: [libc::c_char; 4096] = [0; 4096];
        let mut stats: *mut Stat = 0 as *mut Stat;
        let mut nstats: libc::c_int = 10 as libc::c_int;
        let mut count: libc::c_int = 0 as libc::c_int;
        let mut i: libc::c_int = 0;
        stats = crate::xmalloc::xcalloc(
            nstats as size_t,
            ::core::mem::size_of::<Stat>() as libc::c_ulong,
        ) as *mut Stat;
        loop {
            dp = libc::readdir(dirp);
            if dp.is_null() {
                break;
            }
            if count >= nstats {
                nstats *= 2 as libc::c_int;
                stats = xreallocarray(
                    stats as *mut libc::c_void,
                    nstats as size_t,
                    ::core::mem::size_of::<Stat>() as libc::c_ulong,
                ) as *mut Stat;
            }
            libc::snprintf(
                pathname.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 4096]>() as usize,
                b"%s%s%s\0" as *const u8 as *const libc::c_char,
                path,
                if libc::strcmp(path, b"/\0" as *const u8 as *const libc::c_char) != 0 {
                    b"/\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                ((*dp).d_name).as_mut_ptr(),
            );
            if lstat(pathname.as_mut_ptr(), &mut st) == -(1 as libc::c_int) {
                continue;
            }
            stat_to_attrib(&mut st, &mut (*stats.offset(count as isize)).attrib);
            let ref mut fresh5 = (*stats.offset(count as isize)).name;
            *fresh5 = crate::xmalloc::xstrdup(((*dp).d_name).as_mut_ptr());
            let ref mut fresh6 = (*stats.offset(count as isize)).long_name;
            *fresh6 = ls_file(
                ((*dp).d_name).as_mut_ptr(),
                &mut st,
                0 as libc::c_int,
                0 as libc::c_int,
                0 as *const libc::c_char,
                0 as *const libc::c_char,
            );
            count += 1;
            count;
            if count == 100 as libc::c_int {
                break;
            }
        }
        if count > 0 as libc::c_int {
            send_names(id, count, stats);
            i = 0 as libc::c_int;
            while i < count {
                libc::free((*stats.offset(i as isize)).name as *mut libc::c_void);
                libc::free((*stats.offset(i as isize)).long_name as *mut libc::c_void);
                i += 1;
                i;
            }
        } else {
            send_status(id, 1 as libc::c_int as u_int32_t);
        }
        libc::free(stats as *mut libc::c_void);
    };
}
unsafe extern "C" fn process_remove(mut id: u_int32_t) {
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 4 as libc::c_int;
    r = sshbuf_get_cstring(iqueue, &mut name, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_remove\0"))
                .as_ptr(),
            1192 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_remove\0")).as_ptr(),
        1194 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: remove\0" as *const u8 as *const libc::c_char,
        id,
    );
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_remove\0")).as_ptr(),
        1195 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"remove name \"%s\"\0" as *const u8 as *const libc::c_char,
        name,
    );
    r = unlink(name);
    status = if r == -(1 as libc::c_int) {
        errno_to_portable(*libc::__errno_location())
    } else {
        0 as libc::c_int
    };
    send_status(id, status as u_int32_t);
    libc::free(name as *mut libc::c_void);
}
unsafe extern "C" fn process_mkdir(mut id: u_int32_t) {
    let mut a: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut mode: libc::c_int = 0;
    let mut status: libc::c_int = 4 as libc::c_int;
    r = sshbuf_get_cstring(iqueue, &mut name, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = decode_attrib(iqueue, &mut a);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_mkdir\0"))
                .as_ptr(),
            1211 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    mode = (if a.flags & 0x4 as libc::c_int as libc::c_uint != 0 {
        a.perm & 0o7777 as libc::c_int as libc::c_uint
    } else {
        0o777 as libc::c_int as libc::c_uint
    }) as libc::c_int;
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_mkdir\0")).as_ptr(),
        1215 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: mkdir\0" as *const u8 as *const libc::c_char,
        id,
    );
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_mkdir\0")).as_ptr(),
        1216 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"mkdir name \"%s\" mode 0%o\0" as *const u8 as *const libc::c_char,
        name,
        mode,
    );
    r = libc::mkdir(name, mode as __mode_t);
    status = if r == -(1 as libc::c_int) {
        errno_to_portable(*libc::__errno_location())
    } else {
        0 as libc::c_int
    };
    send_status(id, status as u_int32_t);
    libc::free(name as *mut libc::c_void);
}
unsafe extern "C" fn process_rmdir(mut id: u_int32_t) {
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 0;
    r = sshbuf_get_cstring(iqueue, &mut name, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_rmdir\0"))
                .as_ptr(),
            1230 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_rmdir\0")).as_ptr(),
        1232 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: rmdir\0" as *const u8 as *const libc::c_char,
        id,
    );
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"process_rmdir\0")).as_ptr(),
        1233 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"rmdir name \"%s\"\0" as *const u8 as *const libc::c_char,
        name,
    );
    r = rmdir(name);
    status = if r == -(1 as libc::c_int) {
        errno_to_portable(*libc::__errno_location())
    } else {
        0 as libc::c_int
    };
    send_status(id, status as u_int32_t);
    libc::free(name as *mut libc::c_void);
}
unsafe extern "C" fn process_realpath(mut id: u_int32_t) {
    let mut resolvedname: [libc::c_char; 4096] = [0; 4096];
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    r = sshbuf_get_cstring(iqueue, &mut path, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_realpath\0"))
                .as_ptr(),
            1248 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if *path.offset(0 as libc::c_int as isize) as libc::c_int == '\0' as i32 {
        libc::free(path as *mut libc::c_void);
        path = crate::xmalloc::xstrdup(b".\0" as *const u8 as *const libc::c_char);
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_realpath\0")).as_ptr(),
        1254 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: realpath\0" as *const u8 as *const libc::c_char,
        id,
    );
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_realpath\0")).as_ptr(),
        1255 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_VERBOSE,
        0 as *const libc::c_char,
        b"realpath \"%s\"\0" as *const u8 as *const libc::c_char,
        path,
    );
    if (sftp_realpath(path, resolvedname.as_mut_ptr())).is_null() {
        send_status(
            id,
            errno_to_portable(*libc::__errno_location()) as u_int32_t,
        );
    } else {
        let mut s: Stat = Stat {
            name: 0 as *mut libc::c_char,
            long_name: 0 as *mut libc::c_char,
            attrib: Attrib {
                flags: 0,
                size: 0,
                uid: 0,
                gid: 0,
                perm: 0,
                atime: 0,
                mtime: 0,
            },
        };
        attrib_clear(&mut s.attrib);
        s.long_name = resolvedname.as_mut_ptr();
        s.name = s.long_name;
        send_names(id, 1 as libc::c_int, &mut s);
    }
    libc::free(path as *mut libc::c_void);
}
unsafe extern "C" fn process_rename(mut id: u_int32_t) {
    let mut oldpath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut newpath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 0;
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    r = sshbuf_get_cstring(iqueue, &mut oldpath, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_cstring(iqueue, &mut newpath, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_rename\0"))
                .as_ptr(),
            1276 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_rename\0")).as_ptr(),
        1278 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: rename\0" as *const u8 as *const libc::c_char,
        id,
    );
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_rename\0")).as_ptr(),
        1279 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"rename old \"%s\" new \"%s\"\0" as *const u8 as *const libc::c_char,
        oldpath,
        newpath,
    );
    status = 4 as libc::c_int;
    if lstat(oldpath, &mut sb) == -(1 as libc::c_int) {
        status = errno_to_portable(*libc::__errno_location());
    } else if sb.st_mode & 0o170000 as libc::c_int as libc::c_uint
        == 0o100000 as libc::c_int as libc::c_uint
    {
        if link(oldpath, newpath) == -(1 as libc::c_int) {
            if *libc::__errno_location() == 95 as libc::c_int
                || *libc::__errno_location() == 38 as libc::c_int
                || *libc::__errno_location() == 18 as libc::c_int
                || *libc::__errno_location() == 1 as libc::c_int
            {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                if libc::stat(newpath, &mut st) == -(1 as libc::c_int) {
                    if rename(oldpath, newpath) == -(1 as libc::c_int) {
                        status = errno_to_portable(*libc::__errno_location());
                    } else {
                        status = 0 as libc::c_int;
                    }
                }
            } else {
                status = errno_to_portable(*libc::__errno_location());
            }
        } else if unlink(oldpath) == -(1 as libc::c_int) {
            status = errno_to_portable(*libc::__errno_location());
            unlink(newpath);
        } else {
            status = 0 as libc::c_int;
        }
    } else if libc::stat(newpath, &mut sb) == -(1 as libc::c_int) {
        if rename(oldpath, newpath) == -(1 as libc::c_int) {
            status = errno_to_portable(*libc::__errno_location());
        } else {
            status = 0 as libc::c_int;
        }
    }
    send_status(id, status as u_int32_t);
    libc::free(oldpath as *mut libc::c_void);
    libc::free(newpath as *mut libc::c_void);
}
unsafe extern "C" fn process_readlink(mut id: u_int32_t) {
    let mut r: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut buf: [libc::c_char; 4096] = [0; 4096];
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    r = sshbuf_get_cstring(iqueue, &mut path, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_readlink\0"))
                .as_ptr(),
            1335 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_readlink\0")).as_ptr(),
        1337 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: readlink\0" as *const u8 as *const libc::c_char,
        id,
    );
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_readlink\0")).as_ptr(),
        1338 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_VERBOSE,
        0 as *const libc::c_char,
        b"readlink \"%s\"\0" as *const u8 as *const libc::c_char,
        path,
    );
    len = readlink(
        path,
        buf.as_mut_ptr(),
        (::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    ) as libc::c_int;
    if len == -(1 as libc::c_int) {
        send_status(
            id,
            errno_to_portable(*libc::__errno_location()) as u_int32_t,
        );
    } else {
        let mut s: Stat = Stat {
            name: 0 as *mut libc::c_char,
            long_name: 0 as *mut libc::c_char,
            attrib: Attrib {
                flags: 0,
                size: 0,
                uid: 0,
                gid: 0,
                perm: 0,
                atime: 0,
                mtime: 0,
            },
        };
        buf[len as usize] = '\0' as i32 as libc::c_char;
        attrib_clear(&mut s.attrib);
        s.long_name = buf.as_mut_ptr();
        s.name = s.long_name;
        send_names(id, 1 as libc::c_int, &mut s);
    }
    libc::free(path as *mut libc::c_void);
}
unsafe extern "C" fn process_symlink(mut id: u_int32_t) {
    let mut oldpath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut newpath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 0;
    r = sshbuf_get_cstring(iqueue, &mut oldpath, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_cstring(iqueue, &mut newpath, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_symlink\0"))
                .as_ptr(),
            1360 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_symlink\0")).as_ptr(),
        1362 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: symlink\0" as *const u8 as *const libc::c_char,
        id,
    );
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"process_symlink\0")).as_ptr(),
        1363 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"symlink old \"%s\" new \"%s\"\0" as *const u8 as *const libc::c_char,
        oldpath,
        newpath,
    );
    r = symlink(oldpath, newpath);
    status = if r == -(1 as libc::c_int) {
        errno_to_portable(*libc::__errno_location())
    } else {
        0 as libc::c_int
    };
    send_status(id, status as u_int32_t);
    libc::free(oldpath as *mut libc::c_void);
    libc::free(newpath as *mut libc::c_void);
}
unsafe extern "C" fn process_extended_posix_rename(mut id: u_int32_t) {
    let mut oldpath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut newpath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 0;
    r = sshbuf_get_cstring(iqueue, &mut oldpath, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_cstring(iqueue, &mut newpath, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"process_extended_posix_rename\0",
            ))
            .as_ptr(),
            1380 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
            b"process_extended_posix_rename\0",
        ))
        .as_ptr(),
        1382 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: posix-rename\0" as *const u8 as *const libc::c_char,
        id,
    );
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
            b"process_extended_posix_rename\0",
        ))
        .as_ptr(),
        1383 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"posix-rename old \"%s\" new \"%s\"\0" as *const u8 as *const libc::c_char,
        oldpath,
        newpath,
    );
    r = rename(oldpath, newpath);
    status = if r == -(1 as libc::c_int) {
        errno_to_portable(*libc::__errno_location())
    } else {
        0 as libc::c_int
    };
    send_status(id, status as u_int32_t);
    libc::free(oldpath as *mut libc::c_void);
    libc::free(newpath as *mut libc::c_void);
}
unsafe extern "C" fn process_extended_statvfs(mut id: u_int32_t) {
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut st: statvfs = statvfs {
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
        __f_spare: [0; 6],
    };
    let mut r: libc::c_int = 0;
    r = sshbuf_get_cstring(iqueue, &mut path, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"process_extended_statvfs\0",
            ))
            .as_ptr(),
            1399 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"process_extended_statvfs\0"))
            .as_ptr(),
        1400 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: statvfs\0" as *const u8 as *const libc::c_char,
        id,
    );
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"process_extended_statvfs\0"))
            .as_ptr(),
        1401 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"statvfs \"%s\"\0" as *const u8 as *const libc::c_char,
        path,
    );
    if statvfs(path, &mut st) != 0 as libc::c_int {
        send_status(
            id,
            errno_to_portable(*libc::__errno_location()) as u_int32_t,
        );
    } else {
        send_statvfs(id, &mut st);
    }
    libc::free(path as *mut libc::c_void);
}
unsafe extern "C" fn process_extended_fstatvfs(mut id: u_int32_t) {
    let mut r: libc::c_int = 0;
    let mut handle: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut st: statvfs = statvfs {
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
        __f_spare: [0; 6],
    };
    r = get_handle(iqueue, &mut handle);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"process_extended_fstatvfs\0",
            ))
            .as_ptr(),
            1417 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"process_extended_fstatvfs\0"))
            .as_ptr(),
        1419 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: fstatvfs \"%s\" (handle %u)\0" as *const u8 as *const libc::c_char,
        id,
        handle_to_name(handle),
        handle,
    );
    fd = handle_to_fd(handle);
    if fd < 0 as libc::c_int {
        send_status(id, 4 as libc::c_int as u_int32_t);
        return;
    }
    if fstatvfs(fd, &mut st) != 0 as libc::c_int {
        send_status(
            id,
            errno_to_portable(*libc::__errno_location()) as u_int32_t,
        );
    } else {
        send_statvfs(id, &mut st);
    };
}
unsafe extern "C" fn process_extended_hardlink(mut id: u_int32_t) {
    let mut oldpath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut newpath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 0;
    r = sshbuf_get_cstring(iqueue, &mut oldpath, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_cstring(iqueue, &mut newpath, 0 as *mut size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"process_extended_hardlink\0",
            ))
            .as_ptr(),
            1438 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"process_extended_hardlink\0"))
            .as_ptr(),
        1440 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: hardlink\0" as *const u8 as *const libc::c_char,
        id,
    );
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"process_extended_hardlink\0"))
            .as_ptr(),
        1441 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"hardlink old \"%s\" new \"%s\"\0" as *const u8 as *const libc::c_char,
        oldpath,
        newpath,
    );
    r = link(oldpath, newpath);
    status = if r == -(1 as libc::c_int) {
        errno_to_portable(*libc::__errno_location())
    } else {
        0 as libc::c_int
    };
    send_status(id, status as u_int32_t);
    libc::free(oldpath as *mut libc::c_void);
    libc::free(newpath as *mut libc::c_void);
}
unsafe extern "C" fn process_extended_fsync(mut id: u_int32_t) {
    let mut handle: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 8 as libc::c_int;
    r = get_handle(iqueue, &mut handle);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"process_extended_fsync\0",
            ))
            .as_ptr(),
            1455 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"process_extended_fsync\0"))
            .as_ptr(),
        1456 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: fsync (handle %u)\0" as *const u8 as *const libc::c_char,
        id,
        handle,
    );
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"process_extended_fsync\0"))
            .as_ptr(),
        1457 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_VERBOSE,
        0 as *const libc::c_char,
        b"fsync \"%s\"\0" as *const u8 as *const libc::c_char,
        handle_to_name(handle),
    );
    fd = handle_to_fd(handle);
    if fd < 0 as libc::c_int {
        status = 2 as libc::c_int;
    } else if handle_is_ok(handle, HANDLE_FILE as libc::c_int) != 0 {
        r = fsync(fd);
        status = if r == -(1 as libc::c_int) {
            errno_to_portable(*libc::__errno_location())
        } else {
            0 as libc::c_int
        };
    }
    send_status(id, status as u_int32_t);
}
unsafe extern "C" fn process_extended_lsetstat(mut id: u_int32_t) {
    let mut a: Attrib = Attrib {
        flags: 0,
        size: 0,
        uid: 0,
        gid: 0,
        perm: 0,
        atime: 0,
        mtime: 0,
    };
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 0 as libc::c_int;
    r = sshbuf_get_cstring(iqueue, &mut name, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = decode_attrib(iqueue, &mut a);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"process_extended_lsetstat\0",
            ))
            .as_ptr(),
            1476 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"process_extended_lsetstat\0"))
            .as_ptr(),
        1478 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: lsetstat name \"%s\"\0" as *const u8 as *const libc::c_char,
        id,
        name,
    );
    if a.flags & 0x1 as libc::c_int as libc::c_uint != 0 {
        status = 5 as libc::c_int;
    } else {
        if a.flags & 0x4 as libc::c_int as libc::c_uint != 0 {
            crate::log::sshlog(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"process_extended_lsetstat\0",
                ))
                .as_ptr(),
                1485 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"set \"%s\" mode %04o\0" as *const u8 as *const libc::c_char,
                name,
                a.perm,
            );
            r = fchmodat(
                -(100 as libc::c_int),
                name,
                a.perm & 0o7777 as libc::c_int as libc::c_uint,
                0x100 as libc::c_int,
            );
            if r == -(1 as libc::c_int) {
                status = errno_to_portable(*libc::__errno_location());
            }
        }
        if a.flags & 0x8 as libc::c_int as libc::c_uint != 0 {
            let mut buf: [libc::c_char; 64] = [0; 64];
            let mut t: time_t = a.mtime as time_t;
            strftime(
                buf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
                b"%Y%m%d-%H:%M:%S\0" as *const u8 as *const libc::c_char,
                localtime(&mut t),
            );
            crate::log::sshlog(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"process_extended_lsetstat\0",
                ))
                .as_ptr(),
                1497 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"set \"%s\" modtime %s\0" as *const u8 as *const libc::c_char,
                name,
                buf.as_mut_ptr(),
            );
            r = utimensat(
                -(100 as libc::c_int),
                name,
                attrib_to_ts(&mut a) as *const libc::timespec,
                0x100 as libc::c_int,
            );
            if r == -(1 as libc::c_int) {
                status = errno_to_portable(*libc::__errno_location());
            }
        }
        if a.flags & 0x2 as libc::c_int as libc::c_uint != 0 {
            crate::log::sshlog(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"process_extended_lsetstat\0",
                ))
                .as_ptr(),
                1505 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"set \"%s\" owner %lu group %lu\0" as *const u8 as *const libc::c_char,
                name,
                a.uid as u_long,
                a.gid as u_long,
            );
            r = fchownat(
                -(100 as libc::c_int),
                name,
                a.uid,
                a.gid,
                0x100 as libc::c_int,
            );
            if r == -(1 as libc::c_int) {
                status = errno_to_portable(*libc::__errno_location());
            }
        }
    }
    send_status(id, status as u_int32_t);
    libc::free(name as *mut libc::c_void);
}
unsafe extern "C" fn process_extended_limits(mut id: u_int32_t) {
    let mut msg: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    let mut nfiles: uint64_t = 0 as libc::c_int as uint64_t;
    let mut rlim: rlimit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"process_extended_limits\0"))
            .as_ptr(),
        1526 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: limits\0" as *const u8 as *const libc::c_char,
        id,
    );
    if getrlimit(RLIMIT_NOFILE, &mut rlim) != -(1 as libc::c_int)
        && rlim.rlim_cur > 5 as libc::c_int as libc::c_ulong
    {
        nfiles = (rlim.rlim_cur).wrapping_sub(5 as libc::c_int as libc::c_ulong);
    }
    msg = crate::sshbuf::sshbuf_new();
    if msg.is_null() {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"process_extended_limits\0",
            ))
            .as_ptr(),
            1534 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_u8(msg, 201 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, (256 as libc::c_int * 1024 as libc::c_int) as u_int64_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(
                msg,
                (256 as libc::c_int * 1024 as libc::c_int - 1024 as libc::c_int) as u_int64_t,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(
                msg,
                (256 as libc::c_int * 1024 as libc::c_int - 1024 as libc::c_int) as u_int64_t,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(msg, nfiles);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"process_extended_limits\0",
            ))
            .as_ptr(),
            1545 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(msg);
    crate::sshbuf::sshbuf_free(msg);
}
unsafe extern "C" fn process_extended_expand(mut id: u_int32_t) {
    let mut current_block: u64;
    let mut cwd: [libc::c_char; 4096] = [0; 4096];
    let mut resolvedname: [libc::c_char; 4096] = [0; 4096];
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut npath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut s: Stat = Stat {
        name: 0 as *mut libc::c_char,
        long_name: 0 as *mut libc::c_char,
        attrib: Attrib {
            flags: 0,
            size: 0,
            uid: 0,
            gid: 0,
            perm: 0,
            atime: 0,
            mtime: 0,
        },
    };
    r = sshbuf_get_cstring(iqueue, &mut path, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"process_extended_expand\0",
            ))
            .as_ptr(),
            1559 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    if (getcwd(
        cwd.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
    ))
    .is_null()
    {
        send_status(
            id,
            errno_to_portable(*libc::__errno_location()) as u_int32_t,
        );
    } else {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"process_extended_expand\0",
            ))
            .as_ptr(),
            1565 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"request %u: expand, original \"%s\"\0" as *const u8 as *const libc::c_char,
            id,
            path,
        );
        if *path.offset(0 as libc::c_int as isize) as libc::c_int == '\0' as i32 {
            libc::free(path as *mut libc::c_void);
            path = crate::xmalloc::xstrdup(b".\0" as *const u8 as *const libc::c_char);
            current_block = 17478428563724192186;
        } else if *path as libc::c_int == '~' as i32 {
            if libc::strcmp(path, b"~\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
                libc::free(path as *mut libc::c_void);
                path = crate::xmalloc::xstrdup(cwd.as_mut_ptr());
                current_block = 17478428563724192186;
            } else if strncmp(
                path,
                b"~/\0" as *const u8 as *const libc::c_char,
                2 as libc::c_int as libc::c_ulong,
            ) == 0 as libc::c_int
            {
                npath = crate::xmalloc::xstrdup(path.offset(2 as libc::c_int as isize));
                libc::free(path as *mut libc::c_void);
                crate::xmalloc::xasprintf(
                    &mut path as *mut *mut libc::c_char,
                    b"%s/%s\0" as *const u8 as *const libc::c_char,
                    cwd.as_mut_ptr(),
                    npath,
                );
                libc::free(npath as *mut libc::c_void);
                current_block = 17478428563724192186;
            } else if tilde_expand(path, (*pw).pw_uid, &mut npath) != 0 as libc::c_int {
                send_status_errmsg(
                    id,
                    errno_to_portable(2 as libc::c_int) as u_int32_t,
                    b"no such user\0" as *const u8 as *const libc::c_char,
                );
                current_block = 813749795042461419;
            } else {
                libc::free(path as *mut libc::c_void);
                path = npath;
                current_block = 17478428563724192186;
            }
        } else {
            if *path as libc::c_int != '/' as i32 {
                crate::xmalloc::xasprintf(
                    &mut npath as *mut *mut libc::c_char,
                    b"%s/%s\0" as *const u8 as *const libc::c_char,
                    cwd.as_mut_ptr(),
                    path,
                );
                libc::free(path as *mut libc::c_void);
                path = npath;
            }
            current_block = 17478428563724192186;
        }
        match current_block {
            813749795042461419 => {}
            _ => {
                crate::log::sshlog(
                    b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"process_extended_expand\0",
                    ))
                    .as_ptr(),
                    1597 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_VERBOSE,
                    0 as *const libc::c_char,
                    b"expand \"%s\"\0" as *const u8 as *const libc::c_char,
                    path,
                );
                if (sftp_realpath(path, resolvedname.as_mut_ptr())).is_null() {
                    send_status(
                        id,
                        errno_to_portable(*libc::__errno_location()) as u_int32_t,
                    );
                } else {
                    attrib_clear(&mut s.attrib);
                    s.long_name = resolvedname.as_mut_ptr();
                    s.name = s.long_name;
                    send_names(id, 1 as libc::c_int, &mut s);
                }
            }
        }
    }
    libc::free(path as *mut libc::c_void);
}
unsafe extern "C" fn process_extended_copy_data(mut id: u_int32_t) {
    let mut buf: [u_char; 65536] = [0; 65536];
    let mut read_handle: libc::c_int = 0;
    let mut read_fd: libc::c_int = 0;
    let mut write_handle: libc::c_int = 0;
    let mut write_fd: libc::c_int = 0;
    let mut len: u_int64_t = 0;
    let mut read_off: u_int64_t = 0;
    let mut read_len: u_int64_t = 0;
    let mut write_off: u_int64_t = 0;
    let mut r: libc::c_int = 0;
    let mut copy_until_eof: libc::c_int = 0;
    let mut status: libc::c_int = 8 as libc::c_int;
    let mut ret: size_t = 0;
    r = get_handle(iqueue, &mut read_handle);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_u64(iqueue, &mut read_off);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u64(iqueue, &mut read_len);
            r != 0 as libc::c_int
        }
        || {
            r = get_handle(iqueue, &mut write_handle);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u64(iqueue, &mut write_off);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"process_extended_copy_data\0",
            ))
            .as_ptr(),
            1623 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: buffer error: %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"process_extended_copy_data\0",
            ))
            .as_ptr(),
            ssh_err(r),
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<
            &[u8; 27],
            &[libc::c_char; 27],
        >(b"process_extended_copy_data\0"))
            .as_ptr(),
        1630 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request %u: copy-data from \"%s\" (handle %d) off %llu len %llu to \"%s\" (handle %d) off %llu\0"
            as *const u8 as *const libc::c_char,
        id,
        handle_to_name(read_handle),
        read_handle,
        read_off as libc::c_ulonglong,
        read_len as libc::c_ulonglong,
        handle_to_name(write_handle),
        write_handle,
        write_off as libc::c_ulonglong,
    );
    if read_len == 0 as libc::c_int as libc::c_ulong {
        read_len = (-(1 as libc::c_int) as u_int64_t).wrapping_sub(read_off);
        copy_until_eof = 1 as libc::c_int;
    } else {
        copy_until_eof = 0 as libc::c_int;
    }
    read_fd = handle_to_fd(read_handle);
    write_fd = handle_to_fd(write_handle);
    if read_handle == write_handle
        || read_fd < 0 as libc::c_int
        || write_fd < 0 as libc::c_int
        || libc::strcmp(handle_to_name(read_handle), handle_to_name(write_handle)) == 0
    {
        status = 4 as libc::c_int;
    } else if lseek(read_fd, read_off as __off_t, 0 as libc::c_int)
        < 0 as libc::c_int as libc::c_long
    {
        status = errno_to_portable(*libc::__errno_location());
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"process_extended_copy_data\0",
            ))
            .as_ptr(),
            1651 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s: read_seek failed\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"process_extended_copy_data\0",
            ))
            .as_ptr(),
        );
    } else if handle_to_flags(write_handle) & 0o2000 as libc::c_int == 0 as libc::c_int
        && lseek(write_fd, write_off as __off_t, 0 as libc::c_int)
            < 0 as libc::c_int as libc::c_long
    {
        status = errno_to_portable(*libc::__errno_location());
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"process_extended_copy_data\0",
            ))
            .as_ptr(),
            1658 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s: write_seek failed\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"process_extended_copy_data\0",
            ))
            .as_ptr(),
        );
    } else {
        while read_len > 0 as libc::c_int as libc::c_ulong || copy_until_eof != 0 {
            len = if (::core::mem::size_of::<[u_char; 65536]>() as libc::c_ulong) < read_len {
                ::core::mem::size_of::<[u_char; 65536]>() as libc::c_ulong
            } else {
                read_len
            };
            read_len = (read_len as libc::c_ulong).wrapping_sub(len) as u_int64_t as u_int64_t;
            ret = atomicio(
                Some(
                    read as unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t,
                ),
                read_fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                len,
            );
            if ret == 0 as libc::c_int as libc::c_ulong
                && *libc::__errno_location() == 32 as libc::c_int
            {
                status = if copy_until_eof != 0 {
                    0 as libc::c_int
                } else {
                    1 as libc::c_int
                };
                break;
            } else if ret == 0 as libc::c_int as libc::c_ulong {
                status = errno_to_portable(*libc::__errno_location());
                crate::log::sshlog(
                    b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"process_extended_copy_data\0",
                    ))
                    .as_ptr(),
                    1673 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"%s: read failed: %s\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"process_extended_copy_data\0",
                    ))
                    .as_ptr(),
                    libc::strerror(*libc::__errno_location()),
                );
                break;
            } else {
                len = ret;
                handle_update_read(read_handle, len as ssize_t);
                ret = atomicio(
                    ::core::mem::transmute::<
                        Option<
                            unsafe extern "C" fn(
                                libc::c_int,
                                *const libc::c_void,
                                size_t,
                            ) -> ssize_t,
                        >,
                        Option<
                            unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t,
                        >,
                    >(Some(
                        write
                            as unsafe extern "C" fn(
                                libc::c_int,
                                *const libc::c_void,
                                size_t,
                            ) -> ssize_t,
                    )),
                    write_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    len,
                );
                if ret != len {
                    status = errno_to_portable(*libc::__errno_location());
                    crate::log::sshlog(
                        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"process_extended_copy_data\0",
                        ))
                        .as_ptr(),
                        1684 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s: write failed: %llu != %llu: %s\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                            b"process_extended_copy_data\0",
                        ))
                        .as_ptr(),
                        ret as libc::c_ulonglong,
                        len as libc::c_ulonglong,
                        libc::strerror(*libc::__errno_location()),
                    );
                    break;
                } else {
                    handle_update_write(write_handle, len as ssize_t);
                }
            }
        }
        if read_len == 0 as libc::c_int as libc::c_ulong {
            status = 0 as libc::c_int;
        }
    }
    send_status(id, status as u_int32_t);
}
unsafe extern "C" fn process_extended_home_directory(mut id: u_int32_t) {
    let mut username: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut user_pw: *mut libc::passwd = 0 as *mut libc::passwd;
    let mut r: libc::c_int = 0;
    let mut s: Stat = Stat {
        name: 0 as *mut libc::c_char,
        long_name: 0 as *mut libc::c_char,
        attrib: Attrib {
            flags: 0,
            size: 0,
            uid: 0,
            gid: 0,
            perm: 0,
            atime: 0,
            mtime: 0,
        },
    };
    r = sshbuf_get_cstring(iqueue, &mut username, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 32], &[libc::c_char; 32]>(
                b"process_extended_home_directory\0",
            ))
            .as_ptr(),
            1706 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 32], &[libc::c_char; 32]>(
            b"process_extended_home_directory\0",
        ))
        .as_ptr(),
        1708 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"request %u: home-directory \"%s\"\0" as *const u8 as *const libc::c_char,
        id,
        username,
    );
    user_pw = getpwnam(username);
    if user_pw.is_null() {
        send_status(id, 4 as libc::c_int as u_int32_t);
    } else {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 32], &[libc::c_char; 32]>(
                b"process_extended_home_directory\0",
            ))
            .as_ptr(),
            1714 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"home-directory \"%s\"\0" as *const u8 as *const libc::c_char,
            (*pw).pw_dir,
        );
        attrib_clear(&mut s.attrib);
        s.long_name = (*pw).pw_dir;
        s.name = s.long_name;
        send_names(id, 1 as libc::c_int, &mut s);
    }
    libc::free(username as *mut libc::c_void);
}
unsafe extern "C" fn process_extended_get_users_groups_by_id(mut id: u_int32_t) {
    let mut user_pw: *mut libc::passwd = 0 as *mut libc::passwd;
    let mut gr: *mut group = 0 as *mut group;
    let mut uids: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut gids: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut usernames: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut groupnames: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut msg: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    let mut n: u_int = 0;
    let mut nusers: u_int = 0 as libc::c_int as u_int;
    let mut ngroups: u_int = 0 as libc::c_int as u_int;
    let mut name: *const libc::c_char = 0 as *const libc::c_char;
    usernames = crate::sshbuf::sshbuf_new();
    if usernames.is_null()
        || {
            groupnames = crate::sshbuf::sshbuf_new();
            groupnames.is_null()
        }
        || {
            msg = crate::sshbuf::sshbuf_new();
            msg.is_null()
        }
    {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
                b"process_extended_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            1735 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    r = sshbuf_froms(iqueue, &mut uids);
    if r != 0 as libc::c_int || {
        r = sshbuf_froms(iqueue, &mut gids);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
                b"process_extended_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            1738 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
            b"process_extended_get_users_groups_by_id\0",
        ))
        .as_ptr(),
        1740 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"uids len = %zu, gids len = %zu\0" as *const u8 as *const libc::c_char,
        crate::sshbuf::sshbuf_len(uids),
        crate::sshbuf::sshbuf_len(gids),
    );
    while crate::sshbuf::sshbuf_len(uids) != 0 as libc::c_int as libc::c_ulong {
        r = sshbuf_get_u32(uids, &mut n);
        if r != 0 as libc::c_int {
            sshfatal(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
                    b"process_extended_get_users_groups_by_id\0",
                ))
                .as_ptr(),
                1743 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse inner uid\0" as *const u8 as *const libc::c_char,
            );
        }
        user_pw = libc::getpwuid(n);
        name = if user_pw.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            (*user_pw).pw_name as *const libc::c_char
        };
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
                b"process_extended_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            1746 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"uid %u => \"%s\"\0" as *const u8 as *const libc::c_char,
            n,
            name,
        );
        r = sshbuf_put_cstring(usernames, name);
        if r != 0 as libc::c_int {
            sshfatal(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
                    b"process_extended_get_users_groups_by_id\0",
                ))
                .as_ptr(),
                1748 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble uid reply\0" as *const u8 as *const libc::c_char,
            );
        }
        nusers = nusers.wrapping_add(1);
        nusers;
    }
    while crate::sshbuf::sshbuf_len(gids) != 0 as libc::c_int as libc::c_ulong {
        r = sshbuf_get_u32(gids, &mut n);
        if r != 0 as libc::c_int {
            sshfatal(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
                    b"process_extended_get_users_groups_by_id\0",
                ))
                .as_ptr(),
                1753 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse inner gid\0" as *const u8 as *const libc::c_char,
            );
        }
        gr = getgrgid(n);
        name = if gr.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            (*gr).gr_name as *const libc::c_char
        };
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
                b"process_extended_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            1756 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"gid %u => \"%s\"\0" as *const u8 as *const libc::c_char,
            n,
            name,
        );
        r = sshbuf_put_cstring(groupnames, name);
        if r != 0 as libc::c_int {
            sshfatal(
                b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
                    b"process_extended_get_users_groups_by_id\0",
                ))
                .as_ptr(),
                1758 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"assemble gid reply\0" as *const u8 as *const libc::c_char,
            );
        }
        nusers = nusers.wrapping_add(1);
        nusers;
    }
    crate::log::sshlog(
        b"sftp-server.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
            b"process_extended_get_users_groups_by_id\0",
        ))
        .as_ptr(),
        1761 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_VERBOSE,
        0 as *const libc::c_char,
        b"users-groups-by-id: %u users, %u groups\0" as *const u8 as *const libc::c_char,
        nusers,
        ngroups,
    );
    r = crate::sshbuf_getput_basic::sshbuf_put_u8(msg, 201 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(msg, id);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(msg, usernames);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(msg, groupnames);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 40], &[libc::c_char; 40]>(
                b"process_extended_get_users_groups_by_id\0",
            ))
            .as_ptr(),
            1767 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose\0" as *const u8 as *const libc::c_char,
        );
    }
    send_msg(msg);
    crate::sshbuf::sshbuf_free(uids);
    crate::sshbuf::sshbuf_free(gids);
    crate::sshbuf::sshbuf_free(usernames);
    crate::sshbuf::sshbuf_free(groupnames);
    crate::sshbuf::sshbuf_free(msg);
}
unsafe extern "C" fn process_extended(mut id: u_int32_t) {
    let mut request: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut exthand: *const sftp_handler = 0 as *const sftp_handler;
    r = sshbuf_get_cstring(iqueue, &mut request, 0 as *mut size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_extended\0"))
                .as_ptr(),
            1785 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    }
    exthand = extended_handler_byname(request);
    if exthand.is_null() {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"process_extended\0"))
                .as_ptr(),
            1787 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Unknown extended request \"%.100s\"\0" as *const u8 as *const libc::c_char,
            request,
        );
        send_status(id, 8 as libc::c_int as u_int32_t);
    } else if request_permitted(exthand) == 0 {
        send_status(id, 3 as libc::c_int as u_int32_t);
    } else {
        ((*exthand).handler).expect("non-null function pointer")(id);
    }
    libc::free(request as *mut libc::c_void);
}
unsafe extern "C" fn process() {
    let mut msg_len: u_int = 0;
    let mut buf_len: u_int = 0;
    let mut consumed: u_int = 0;
    let mut type_0: u_char = 0;
    let mut cp: *const u_char = 0 as *const u_char;
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut id: u_int32_t = 0;
    buf_len = crate::sshbuf::sshbuf_len(iqueue) as u_int;
    if buf_len < 5 as libc::c_int as libc::c_uint {
        return;
    }
    cp = sshbuf_ptr(iqueue);
    msg_len = get_u32(cp as *const libc::c_void);
    if msg_len > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_uint {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
            1818 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"bad message from %s local user %s\0" as *const u8 as *const libc::c_char,
            client_addr,
            (*pw).pw_name,
        );
        sftp_server_cleanup_exit(11 as libc::c_int);
    }
    if buf_len < msg_len.wrapping_add(4 as libc::c_int as libc::c_uint) {
        return;
    }
    r = sshbuf_consume(iqueue, 4 as libc::c_int as size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
            1824 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"consume\0" as *const u8 as *const libc::c_char,
        );
    }
    buf_len =
        (buf_len as libc::c_uint).wrapping_sub(4 as libc::c_int as libc::c_uint) as u_int as u_int;
    r = sshbuf_get_u8(iqueue, &mut type_0);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
            1827 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse type\0" as *const u8 as *const libc::c_char,
        );
    }
    match type_0 as libc::c_int {
        1 => {
            process_init();
            init_done = 1 as libc::c_int;
        }
        200 => {
            if init_done == 0 {
                sshfatal(
                    b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0"))
                        .as_ptr(),
                    1836 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Received extended request before init\0" as *const u8 as *const libc::c_char,
                );
            }
            r = sshbuf_get_u32(iqueue, &mut id);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0"))
                        .as_ptr(),
                    1838 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse extended ID\0" as *const u8 as *const libc::c_char,
                );
            }
            process_extended(id);
        }
        _ => {
            if init_done == 0 {
                sshfatal(
                    b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0"))
                        .as_ptr(),
                    1843 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Received %u request before init\0" as *const u8 as *const libc::c_char,
                    type_0 as libc::c_int,
                );
            }
            r = sshbuf_get_u32(iqueue, &mut id);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0"))
                        .as_ptr(),
                    1845 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse ID\0" as *const u8 as *const libc::c_char,
                );
            }
            i = 0 as libc::c_int;
            while (handlers[i as usize].handler).is_some() {
                if type_0 as libc::c_uint == handlers[i as usize].type_0 {
                    if request_permitted(&*handlers.as_ptr().offset(i as isize)) == 0 {
                        send_status(id, 3 as libc::c_int as u_int32_t);
                    } else {
                        (handlers[i as usize].handler).expect("non-null function pointer")(id);
                    }
                    break;
                } else {
                    i += 1;
                    i;
                }
            }
            if (handlers[i as usize].handler).is_none() {
                crate::log::sshlog(
                    b"sftp-server.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0"))
                        .as_ptr(),
                    1858 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Unknown message %u\0" as *const u8 as *const libc::c_char,
                    type_0 as libc::c_int,
                );
            }
        }
    }
    if (buf_len as libc::c_ulong) < crate::sshbuf::sshbuf_len(iqueue) {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
            1862 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"iqueue grew unexpectedly\0" as *const u8 as *const libc::c_char,
        );
        sftp_server_cleanup_exit(255 as libc::c_int);
    }
    consumed = (buf_len as libc::c_ulong).wrapping_sub(crate::sshbuf::sshbuf_len(iqueue)) as u_int;
    if msg_len < consumed {
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
            1867 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"msg_len %u < consumed %u\0" as *const u8 as *const libc::c_char,
            msg_len,
            consumed,
        );
        sftp_server_cleanup_exit(255 as libc::c_int);
    }
    if msg_len > consumed && {
        r = sshbuf_consume(iqueue, msg_len.wrapping_sub(consumed) as size_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"process\0")).as_ptr(),
            1872 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"consume\0" as *const u8 as *const libc::c_char,
        );
    }
}
pub unsafe extern "C" fn sftp_server_cleanup_exit(mut i: libc::c_int) -> ! {
    if !pw.is_null() && !client_addr.is_null() {
        handle_log_exit();
        crate::log::sshlog(
            b"sftp-server.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"sftp_server_cleanup_exit\0",
            ))
            .as_ptr(),
            1882 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"session closed for local user %s from [%s]\0" as *const u8 as *const libc::c_char,
            (*pw).pw_name,
            client_addr,
        );
    }
    libc::_exit(i);
}
unsafe extern "C" fn sftp_server_usage() {
    extern "C" {
        static mut __progname: *mut libc::c_char;
    }
    libc::fprintf(
        stderr,
        b"usage: %s [-ehR] [-d start_directory] [-f log_facility] [-l log_level]\n\t[-P denied_requests] [-p allowed_requests] [-u umask]\n       %s -Q protocol_feature\n\0"
            as *const u8 as *const libc::c_char,
        __progname,
        __progname,
    );
    libc::exit(1 as libc::c_int);
}
