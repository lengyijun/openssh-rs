use ::libc;
extern "C" {

    
    fn geteuid() -> __uid_t;
    fn getgid() -> __gid_t;
    fn getegid() -> __gid_t;
    fn getgroups(__size: libc::c_int, __list: *mut __gid_t) -> libc::c_int;
    fn setuid(__uid: __uid_t) -> libc::c_int;
    fn seteuid(__uid: __uid_t) -> libc::c_int;
    fn setgid(__gid: __gid_t) -> libc::c_int;
    fn setegid(__gid: __gid_t) -> libc::c_int;
    fn setresuid(__ruid: __uid_t, __euid: __uid_t, __suid: __uid_t) -> libc::c_int;
    fn setresgid(__rgid: __gid_t, __egid: __gid_t, __sgid: __gid_t) -> libc::c_int;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;

    fn setgroups(__n: size_t, __groups: *const __gid_t) -> libc::c_int;
    fn initgroups(__user: *const libc::c_char, __group: __gid_t) -> libc::c_int;

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
    fn xreallocarray(_: *mut libc::c_void, _: size_t, _: size_t) -> *mut libc::c_void;
}
pub type __u_int = libc::c_uint;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type u_int = __u_int;
pub type gid_t = __gid_t;
pub type uid_t = __uid_t;
pub type size_t = libc::c_ulong;

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
static mut saved_euid: uid_t = 0 as libc::c_int as uid_t;
static mut saved_egid: gid_t = 0 as libc::c_int as gid_t;
static mut privileged: libc::c_int = 0 as libc::c_int;
static mut temporarily_use_uid_effective: libc::c_int = 0 as libc::c_int;
static mut user_groups_uid: uid_t = 0;
static mut saved_egroups: *mut gid_t = 0 as *const gid_t as *mut gid_t;
static mut user_groups: *mut gid_t = 0 as *const gid_t as *mut gid_t;
static mut saved_egroupslen: libc::c_int = -(1 as libc::c_int);
static mut user_groupslen: libc::c_int = -(1 as libc::c_int);
pub unsafe extern "C" fn temporarily_use_uid(mut pw: *mut libc::passwd) {
    saved_euid = geteuid();
    saved_egid = getegid();
    crate::log::sshlog(
        b"uidswap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"temporarily_use_uid\0"))
            .as_ptr(),
        69 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"temporarily_use_uid: %u/%u (e=%u/%u)\0" as *const u8 as *const libc::c_char,
        (*pw).pw_uid,
        (*pw).pw_gid,
        saved_euid,
        saved_egid,
    );
    if saved_euid != 0 as libc::c_int as libc::c_uint {
        privileged = 0 as libc::c_int;
        return;
    }
    privileged = 1 as libc::c_int;
    temporarily_use_uid_effective = 1 as libc::c_int;
    saved_egroupslen = getgroups(0 as libc::c_int, 0 as *mut __gid_t);
    if saved_egroupslen == -(1 as libc::c_int) {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"temporarily_use_uid\0"))
                .as_ptr(),
            88 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"getgroups: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    if saved_egroupslen > 0 as libc::c_int {
        saved_egroups = xreallocarray(
            saved_egroups as *mut libc::c_void,
            saved_egroupslen as size_t,
            ::core::mem::size_of::<gid_t>() as libc::c_ulong,
        ) as *mut gid_t;
        if getgroups(saved_egroupslen, saved_egroups) == -(1 as libc::c_int) {
            sshfatal(
                b"uidswap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"temporarily_use_uid\0",
                ))
                .as_ptr(),
                93 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"getgroups: %.100s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
    } else {
        libc::free(saved_egroups as *mut libc::c_void);
        saved_egroups = 0 as *mut gid_t;
    }
    if user_groupslen == -(1 as libc::c_int) || user_groups_uid != (*pw).pw_uid {
        if initgroups((*pw).pw_name, (*pw).pw_gid) == -(1 as libc::c_int) {
            sshfatal(
                b"uidswap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"temporarily_use_uid\0",
                ))
                .as_ptr(),
                103 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"initgroups: %s: %.100s\0" as *const u8 as *const libc::c_char,
                (*pw).pw_name,
                strerror(*libc::__errno_location()),
            );
        }
        user_groupslen = getgroups(0 as libc::c_int, 0 as *mut __gid_t);
        if user_groupslen == -(1 as libc::c_int) {
            sshfatal(
                b"uidswap.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"temporarily_use_uid\0",
                ))
                .as_ptr(),
                107 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"getgroups: %.100s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
        if user_groupslen > 0 as libc::c_int {
            user_groups = xreallocarray(
                user_groups as *mut libc::c_void,
                user_groupslen as size_t,
                ::core::mem::size_of::<gid_t>() as libc::c_ulong,
            ) as *mut gid_t;
            if getgroups(user_groupslen, user_groups) == -(1 as libc::c_int) {
                sshfatal(
                    b"uidswap.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"temporarily_use_uid\0",
                    ))
                    .as_ptr(),
                    112 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"getgroups: %.100s\0" as *const u8 as *const libc::c_char,
                    strerror(*libc::__errno_location()),
                );
            }
        } else {
            libc::free(user_groups as *mut libc::c_void);
            user_groups = 0 as *mut gid_t;
        }
        user_groups_uid = (*pw).pw_uid;
    }
    if setgroups(user_groupslen as size_t, user_groups) == -(1 as libc::c_int) {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"temporarily_use_uid\0"))
                .as_ptr(),
            121 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"setgroups: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    if setegid((*pw).pw_gid) == -(1 as libc::c_int) {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"temporarily_use_uid\0"))
                .as_ptr(),
            132 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"setegid %u: %.100s\0" as *const u8 as *const libc::c_char,
            (*pw).pw_gid,
            strerror(*libc::__errno_location()),
        );
    }
    if seteuid((*pw).pw_uid) == -(1 as libc::c_int) {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"temporarily_use_uid\0"))
                .as_ptr(),
            135 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"seteuid %u: %.100s\0" as *const u8 as *const libc::c_char,
            (*pw).pw_uid,
            strerror(*libc::__errno_location()),
        );
    }
}
pub unsafe extern "C" fn restore_uid() {
    if privileged == 0 {
        crate::log::sshlog(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"restore_uid\0")).as_ptr(),
            146 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"restore_uid: (unprivileged)\0" as *const u8 as *const libc::c_char,
        );
        return;
    }
    if temporarily_use_uid_effective == 0 {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"restore_uid\0")).as_ptr(),
            150 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"restore_uid: temporarily_use_uid not effective\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"uidswap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"restore_uid\0")).as_ptr(),
        153 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"restore_uid: %u/%u\0" as *const u8 as *const libc::c_char,
        saved_euid,
        saved_egid,
    );
    if seteuid(saved_euid) == -(1 as libc::c_int) {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"restore_uid\0")).as_ptr(),
            156 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"seteuid %u: %.100s\0" as *const u8 as *const libc::c_char,
            saved_euid,
            strerror(*libc::__errno_location()),
        );
    }
    if setegid(saved_egid) == -(1 as libc::c_int) {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"restore_uid\0")).as_ptr(),
            158 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"setegid %u: %.100s\0" as *const u8 as *const libc::c_char,
            saved_egid,
            strerror(*libc::__errno_location()),
        );
    }
    if setgroups(saved_egroupslen as size_t, saved_egroups) == -(1 as libc::c_int) {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"restore_uid\0")).as_ptr(),
            172 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"setgroups: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    temporarily_use_uid_effective = 0 as libc::c_int;
}
pub unsafe extern "C" fn permanently_set_uid(mut pw: *mut libc::passwd) {
    let mut old_uid: uid_t = libc::getuid();
    let mut old_gid: gid_t = getgid();
    if pw.is_null() {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"permanently_set_uid\0"))
                .as_ptr(),
            189 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"permanently_set_uid: no user given\0" as *const u8 as *const libc::c_char,
        );
    }
    if temporarily_use_uid_effective != 0 {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"permanently_set_uid\0"))
                .as_ptr(),
            191 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"permanently_set_uid: temporarily_use_uid effective\0" as *const u8
                as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"uidswap.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"permanently_set_uid\0"))
            .as_ptr(),
        193 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"permanently_set_uid: %u/%u\0" as *const u8 as *const libc::c_char,
        (*pw).pw_uid,
        (*pw).pw_gid,
    );
    if setresgid((*pw).pw_gid, (*pw).pw_gid, (*pw).pw_gid) == -(1 as libc::c_int) {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"permanently_set_uid\0"))
                .as_ptr(),
            196 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"setresgid %u: %.100s\0" as *const u8 as *const libc::c_char,
            (*pw).pw_gid,
            strerror(*libc::__errno_location()),
        );
    }
    if setresuid((*pw).pw_uid, (*pw).pw_uid, (*pw).pw_uid) == -(1 as libc::c_int) {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"permanently_set_uid\0"))
                .as_ptr(),
            209 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"setresuid %u: %.100s\0" as *const u8 as *const libc::c_char,
            (*pw).pw_uid,
            strerror(*libc::__errno_location()),
        );
    }
    if old_gid != (*pw).pw_gid
        && (*pw).pw_uid != 0 as libc::c_int as libc::c_uint
        && (setgid(old_gid) != -(1 as libc::c_int) || setegid(old_gid) != -(1 as libc::c_int))
    {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"permanently_set_uid\0"))
                .as_ptr(),
            215 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: was able to restore old [e]gid\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"permanently_set_uid\0"))
                .as_ptr(),
        );
    }
    if getgid() != (*pw).pw_gid || getegid() != (*pw).pw_gid {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"permanently_set_uid\0"))
                .as_ptr(),
            222 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: egid incorrect gid:%u egid:%u (should be %u)\0" as *const u8
                as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"permanently_set_uid\0"))
                .as_ptr(),
            getgid(),
            getegid(),
            (*pw).pw_gid,
        );
    }
    if old_uid != (*pw).pw_uid
        && (setuid(old_uid) != -(1 as libc::c_int) || seteuid(old_uid) != -(1 as libc::c_int))
    {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"permanently_set_uid\0"))
                .as_ptr(),
            229 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: was able to restore old [e]uid\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"permanently_set_uid\0"))
                .as_ptr(),
        );
    }
    if libc::getuid() != (*pw).pw_uid || geteuid() != (*pw).pw_uid {
        sshfatal(
            b"uidswap.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"permanently_set_uid\0"))
                .as_ptr(),
            236 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: euid incorrect uid:%u euid:%u (should be %u)\0" as *const u8
                as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"permanently_set_uid\0"))
                .as_ptr(),
            libc::getuid(),
            geteuid(),
            (*pw).pw_uid,
        );
    }
}
