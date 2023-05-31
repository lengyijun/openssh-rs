use crate::servconf::ServerOptions;

use ::libc;

use libc::close;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn innetgr(
        __netgroup: *const libc::c_char,
        __host: *const libc::c_char,
        __user: *const libc::c_char,
        __domain: *const libc::c_char,
    ) -> libc::c_int;
    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;

    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn fgets(
        __s: *mut libc::c_char,
        __n: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> *mut libc::c_char;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;

    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;

    fn temporarily_use_uid(_: *mut libc::passwd);
    fn restore_uid();

    fn auth_debug_add(fmt: *const libc::c_char, _: ...);
    static mut options: ServerOptions;
}
pub type __u_int = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int64_t = __uint64_t;

pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;

pub type _IO_lock_t = ();

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

unsafe extern "C" fn check_rhosts_file(
    mut filename: *const libc::c_char,
    mut hostname: *const libc::c_char,
    mut ipaddr: *const libc::c_char,
    mut client_user: *const libc::c_char,
    mut server_user: *const libc::c_char,
) -> libc::c_int {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut fd: libc::c_int = 0;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    fd = libc::open(filename, 0 as libc::c_int | 0o4000 as libc::c_int);
    if fd == -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    if libc::fstat(fd, &mut st) == -(1 as libc::c_int) {
        close(fd);
        return 0 as libc::c_int;
    }
    if !(st.st_mode & 0o170000 as libc::c_int as libc::c_uint
        == 0o100000 as libc::c_int as libc::c_uint)
    {
        crate::log::sshlog(
            b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"check_rhosts_file\0"))
                .as_ptr(),
            77 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"User %s hosts file %s is not a regular file\0" as *const u8 as *const libc::c_char,
            server_user,
            filename,
        );
        close(fd);
        return 0 as libc::c_int;
    }
    crate::misc::unset_nonblock(fd);
    f = libc::fdopen(fd, b"r\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        close(fd);
        return 0 as libc::c_int;
    }
    while !(fgets(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong as libc::c_int,
        f,
    ))
    .is_null()
    {
        let mut hostbuf: [libc::c_char; 1024] = [0; 1024];
        let mut userbuf: [libc::c_char; 1024] = [0; 1024];
        let mut dummy: [libc::c_char; 1024] = [0; 1024];
        let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut negated: libc::c_int = 0;
        cp = buf.as_mut_ptr();
        while *cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32 {
            cp = cp.offset(1);
            cp;
        }
        if *cp as libc::c_int == '#' as i32 || *cp as libc::c_int == '\n' as i32 || *cp == 0 {
            continue;
        }
        if strncmp(
            cp,
            b"NO_PLUS\0" as *const u8 as *const libc::c_char,
            7 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            continue;
        }
        match sscanf(
            buf.as_mut_ptr(),
            b"%1023s %1023s %1023s\0" as *const u8 as *const libc::c_char,
            hostbuf.as_mut_ptr(),
            userbuf.as_mut_ptr(),
            dummy.as_mut_ptr(),
        ) {
            0 => {
                auth_debug_add(
                    b"Found empty line in %.100s.\0" as *const u8 as *const libc::c_char,
                    filename,
                );
                continue;
            }
            1 => {
                strlcpy(
                    userbuf.as_mut_ptr(),
                    server_user,
                    ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
                );
            }
            2 => {}
            3 => {
                auth_debug_add(
                    b"Found garbage in %.100s.\0" as *const u8 as *const libc::c_char,
                    filename,
                );
                continue;
            }
            _ => {
                continue;
            }
        }
        host = hostbuf.as_mut_ptr();
        user = userbuf.as_mut_ptr();
        negated = 0 as libc::c_int;
        if *host.offset(0 as libc::c_int as isize) as libc::c_int == '-' as i32 {
            negated = 1 as libc::c_int;
            host = host.offset(1);
            host;
        } else if *host.offset(0 as libc::c_int as isize) as libc::c_int == '+' as i32 {
            host = host.offset(1);
            host;
        }
        if *user.offset(0 as libc::c_int as isize) as libc::c_int == '-' as i32 {
            negated = 1 as libc::c_int;
            user = user.offset(1);
            user;
        } else if *user.offset(0 as libc::c_int as isize) as libc::c_int == '+' as i32 {
            user = user.offset(1);
            user;
        }
        if *host.offset(0 as libc::c_int as isize) == 0
            || *user.offset(0 as libc::c_int as isize) == 0
        {
            auth_debug_add(
                b"Ignoring wild host/user names in %.100s.\0" as *const u8 as *const libc::c_char,
                filename,
            );
        } else {
            if *host.offset(0 as libc::c_int as isize) as libc::c_int == '@' as i32 {
                if innetgr(
                    host.offset(1 as libc::c_int as isize),
                    hostname,
                    0 as *const libc::c_char,
                    0 as *const libc::c_char,
                ) == 0
                    && innetgr(
                        host.offset(1 as libc::c_int as isize),
                        ipaddr,
                        0 as *const libc::c_char,
                        0 as *const libc::c_char,
                    ) == 0
                {
                    continue;
                }
            } else if strcasecmp(host, hostname) != 0
                && libc::strcmp(host, ipaddr) != 0 as libc::c_int
            {
                continue;
            }
            if *user.offset(0 as libc::c_int as isize) as libc::c_int == '@' as i32 {
                if innetgr(
                    user.offset(1 as libc::c_int as isize),
                    0 as *const libc::c_char,
                    client_user,
                    0 as *const libc::c_char,
                ) == 0
                {
                    continue;
                }
            } else if libc::strcmp(user, client_user) != 0 as libc::c_int {
                continue;
            }
            fclose(f);
            if negated != 0 {
                auth_debug_add(
                    b"Matched negative entry in %.100s.\0" as *const u8 as *const libc::c_char,
                    filename,
                );
                return 0 as libc::c_int;
            }
            return 1 as libc::c_int;
        }
    }
    fclose(f);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn auth_rhosts2(
    mut pw: *mut libc::passwd,
    mut client_user: *const libc::c_char,
    mut hostname: *const libc::c_char,
    mut ipaddr: *const libc::c_char,
) -> libc::c_int {
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    static mut rhosts_files: [*const libc::c_char; 3] = [
        b".shosts\0" as *const u8 as *const libc::c_char,
        b".rhosts\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    let mut rhosts_file_index: u_int = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"auth_rhosts2\0")).as_ptr(),
        202 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"clientuser %s hostname %s ipaddr %s\0" as *const u8 as *const libc::c_char,
        client_user,
        hostname,
        ipaddr,
    );
    temporarily_use_uid(pw);
    rhosts_file_index = 0 as libc::c_int as u_int;
    while !(rhosts_files[rhosts_file_index as usize]).is_null() {
        crate::xmalloc::xasprintf(
            &mut path as *mut *mut libc::c_char,
            b"%s/%s\0" as *const u8 as *const libc::c_char,
            (*pw).pw_dir,
            rhosts_files[rhosts_file_index as usize],
        );
        r = libc::stat(path, &mut st);
        libc::free(path as *mut libc::c_void);
        if r >= 0 as libc::c_int {
            break;
        }
        rhosts_file_index = rhosts_file_index.wrapping_add(1);
        rhosts_file_index;
    }
    restore_uid();
    if (rhosts_files[rhosts_file_index as usize]).is_null()
        && libc::stat(
            b"/etc/hosts.equiv\0" as *const u8 as *const libc::c_char,
            &mut st,
        ) == -(1 as libc::c_int)
        && libc::stat(
            b"/usr/local/etc/shosts.equiv\0" as *const u8 as *const libc::c_char,
            &mut st,
        ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"auth_rhosts2\0")).as_ptr(),
            232 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"no hosts access files exist\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if (*pw).pw_uid == 0 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"auth_rhosts2\0")).as_ptr(),
            241 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"root user, ignoring system hosts files\0" as *const u8 as *const libc::c_char,
        );
    } else {
        if check_rhosts_file(
            b"/etc/hosts.equiv\0" as *const u8 as *const libc::c_char,
            hostname,
            ipaddr,
            client_user,
            (*pw).pw_name,
        ) != 0
        {
            auth_debug_add(
                b"Accepted for %.100s [%.100s] by /etc/hosts.equiv.\0" as *const u8
                    as *const libc::c_char,
                hostname,
                ipaddr,
            );
            return 1 as libc::c_int;
        }
        if check_rhosts_file(
            b"/usr/local/etc/shosts.equiv\0" as *const u8 as *const libc::c_char,
            hostname,
            ipaddr,
            client_user,
            (*pw).pw_name,
        ) != 0
        {
            auth_debug_add(
                b"Accepted for %.100s [%.100s] by %.100s.\0" as *const u8 as *const libc::c_char,
                hostname,
                ipaddr,
                b"/usr/local/etc/shosts.equiv\0" as *const u8 as *const libc::c_char,
            );
            return 1 as libc::c_int;
        }
    }
    if libc::stat((*pw).pw_dir, &mut st) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"auth_rhosts2\0")).as_ptr(),
            263 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Rhosts authentication refused for %.100s: no home directory %.200s\0" as *const u8
                as *const libc::c_char,
            (*pw).pw_name,
            (*pw).pw_dir,
        );
        auth_debug_add(
            b"Rhosts authentication refused for %.100s: no home directory %.200s\0" as *const u8
                as *const libc::c_char,
            (*pw).pw_name,
            (*pw).pw_dir,
        );
        return 0 as libc::c_int;
    }
    if options.strict_modes != 0
        && (st.st_uid != 0 as libc::c_int as libc::c_uint && st.st_uid != (*pw).pw_uid
            || st.st_mode & 0o22 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint)
    {
        crate::log::sshlog(
            b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<
                &[u8; 13],
                &[libc::c_char; 13],
            >(b"auth_rhosts2\0"))
                .as_ptr(),
            272 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Rhosts authentication refused for %.100s: bad ownership or modes for home directory.\0"
                as *const u8 as *const libc::c_char,
            (*pw).pw_name,
        );
        auth_debug_add(
            b"Rhosts authentication refused for %.100s: bad ownership or modes for home directory.\0"
                as *const u8 as *const libc::c_char,
            (*pw).pw_name,
        );
        return 0 as libc::c_int;
    }
    temporarily_use_uid(pw);
    rhosts_file_index = 0 as libc::c_int as u_int;
    while !(rhosts_files[rhosts_file_index as usize]).is_null() {
        crate::xmalloc::xasprintf(
            &mut path as *mut *mut libc::c_char,
            b"%s/%s\0" as *const u8 as *const libc::c_char,
            (*pw).pw_dir,
            rhosts_files[rhosts_file_index as usize],
        );
        if libc::stat(path, &mut st) == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"auth_rhosts2\0"))
                    .as_ptr(),
                287 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"libc::stat %s: %s\0" as *const u8 as *const libc::c_char,
                path,
                libc::strerror(*libc::__errno_location()),
            );
            libc::free(path as *mut libc::c_void);
        } else if options.strict_modes != 0
            && (st.st_uid != 0 as libc::c_int as libc::c_uint && st.st_uid != (*pw).pw_uid
                || st.st_mode & 0o22 as libc::c_int as libc::c_uint
                    != 0 as libc::c_int as libc::c_uint)
        {
            crate::log::sshlog(
                b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"auth_rhosts2\0"))
                    .as_ptr(),
                302 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Rhosts authentication refused for %.100s: bad modes for %.200s\0" as *const u8
                    as *const libc::c_char,
                (*pw).pw_name,
                path,
            );
            auth_debug_add(
                b"Bad file modes for %.200s\0" as *const u8 as *const libc::c_char,
                path,
            );
            libc::free(path as *mut libc::c_void);
        } else if options.ignore_rhosts == 1 as libc::c_int
            || options.ignore_rhosts == 2 as libc::c_int
                && libc::strcmp(
                    rhosts_files[rhosts_file_index as usize],
                    b".shosts\0" as *const u8 as *const libc::c_char,
                ) != 0 as libc::c_int
        {
            auth_debug_add(
                b"Server has been configured to ignore %.100s.\0" as *const u8
                    as *const libc::c_char,
                rhosts_files[rhosts_file_index as usize],
            );
            libc::free(path as *mut libc::c_void);
        } else {
            if check_rhosts_file(path, hostname, ipaddr, client_user, (*pw).pw_name) != 0 {
                auth_debug_add(
                    b"Accepted by %.100s.\0" as *const u8 as *const libc::c_char,
                    rhosts_files[rhosts_file_index as usize],
                );
                restore_uid();
                auth_debug_add(
                    b"Accepted host %s ip %s client_user %s server_user %s\0" as *const u8
                        as *const libc::c_char,
                    hostname,
                    ipaddr,
                    client_user,
                    (*pw).pw_name,
                );
                libc::free(path as *mut libc::c_void);
                return 1 as libc::c_int;
            }
            libc::free(path as *mut libc::c_void);
        }
        rhosts_file_index = rhosts_file_index.wrapping_add(1);
        rhosts_file_index;
    }
    restore_uid();
    return 0 as libc::c_int;
}
