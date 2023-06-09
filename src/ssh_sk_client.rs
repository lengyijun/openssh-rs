use crate::ssh_sk::sshsk_resident_key;
use ::libc;
use libc::close;
use libc::pid_t;
extern "C" {

    fn freezero(_: *mut libc::c_void, _: size_t);

    fn access(__name: *const libc::c_char, __type: libc::c_int) -> libc::c_int;

    fn closefrom(__lowfd: libc::c_int);

    fn execlp(__file: *const libc::c_char, __arg: *const libc::c_char, _: ...) -> libc::c_int;

    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;

    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn log_level_get() -> LogLevel;
    fn log_is_on_stderr() -> libc::c_int;

    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;

    fn sshbuf_get_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;

    fn sshbuf_putb(buf: *mut crate::sshbuf::sshbuf, v: *const crate::sshbuf::sshbuf)
        -> libc::c_int;

    fn sshkey_private_serialize(
        key: *mut crate::sshkey::sshkey,
        buf: *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshkey_private_deserialize(
        buf: *mut crate::sshbuf::sshbuf,
        keyp: *mut *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn ssh_msg_send(_: libc::c_int, _: u_char, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn ssh_msg_recv(_: libc::c_int, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;

}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __pid_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;

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
pub type uint8_t = __uint8_t;
pub type __sighandler_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
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
unsafe extern "C" fn start_helper(
    mut fdp: *mut libc::c_int,
    mut pidp: *mut pid_t,
    mut osigchldp: *mut Option<unsafe extern "C" fn(libc::c_int) -> ()>,
) -> libc::c_int {
    let mut osigchld: Option<unsafe extern "C" fn(libc::c_int) -> ()> = None;
    let mut oerrno: libc::c_int = 0;
    let mut pair: [libc::c_int; 2] = [0; 2];
    let mut pid: pid_t = 0;
    let mut helper: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut verbosity: *mut libc::c_char = 0 as *mut libc::c_char;
    *fdp = -(1 as libc::c_int);
    *pidp = 0 as libc::c_int;
    *osigchldp = None;
    helper = getenv(b"SSH_SK_HELPER\0" as *const u8 as *const libc::c_char);
    if helper.is_null() || strlen(helper) == 0 as libc::c_int as libc::c_ulong {
        helper = b"/usr/local/libexec/ssh-sk-helper\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char;
    }
    if access(helper, 1 as libc::c_int) != 0 as libc::c_int {
        oerrno = *libc::__errno_location();
        crate::log::sshlog(
            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"start_helper\0")).as_ptr(),
            63 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"helper \"%s\" unusable: %s\0" as *const u8 as *const libc::c_char,
            helper,
            libc::strerror(*libc::__errno_location()),
        );
        *libc::__errno_location() = oerrno;
        return -(24 as libc::c_int);
    }
    if libc::socketpair(
        1 as libc::c_int,
        SOCK_STREAM as libc::c_int,
        0 as libc::c_int,
        pair.as_mut_ptr(),
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"start_helper\0")).as_ptr(),
            73 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"libc::socketpair: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        return -(24 as libc::c_int);
    }
    osigchld = crate::misc::ssh_signal(17 as libc::c_int, None);
    pid = libc::fork();
    if pid == -(1 as libc::c_int) {
        oerrno = *libc::__errno_location();
        crate::log::sshlog(
            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"start_helper\0")).as_ptr(),
            79 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"libc::fork: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        close(pair[0 as libc::c_int as usize]);
        close(pair[1 as libc::c_int as usize]);
        crate::misc::ssh_signal(17 as libc::c_int, osigchld);
        *libc::__errno_location() = oerrno;
        return -(24 as libc::c_int);
    }
    if pid == 0 as libc::c_int {
        if libc::dup2(pair[1 as libc::c_int as usize], 0 as libc::c_int) == -(1 as libc::c_int)
            || libc::dup2(pair[1 as libc::c_int as usize], 1 as libc::c_int) == -(1 as libc::c_int)
        {
            crate::log::sshlog(
                b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"start_helper\0"))
                    .as_ptr(),
                89 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"libc::dup2: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
            libc::_exit(1 as libc::c_int);
        }
        close(pair[0 as libc::c_int as usize]);
        close(pair[1 as libc::c_int as usize]);
        closefrom(2 as libc::c_int + 1 as libc::c_int);
        crate::log::sshlog(
            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"start_helper\0")).as_ptr(),
            96 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"starting %s %s\0" as *const u8 as *const libc::c_char,
            helper,
            if verbosity.is_null() {
                b"\0" as *const u8 as *const libc::c_char
            } else {
                verbosity as *const libc::c_char
            },
        );
        execlp(
            helper,
            helper,
            verbosity,
            0 as *mut libc::c_void as *mut libc::c_char,
        );
        crate::log::sshlog(
            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"start_helper\0")).as_ptr(),
            98 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"execlp: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        libc::_exit(1 as libc::c_int);
    }
    close(pair[1 as libc::c_int as usize]);
    crate::log::sshlog(
        b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"start_helper\0")).as_ptr(),
        104 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"started pid=%ld\0" as *const u8 as *const libc::c_char,
        pid as libc::c_long,
    );
    *fdp = pair[0 as libc::c_int as usize];
    *pidp = pid;
    *osigchldp = osigchld;
    return 0 as libc::c_int;
}
unsafe extern "C" fn reap_helper(mut pid: pid_t) -> libc::c_int {
    let mut status: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    crate::log::sshlog(
        b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"reap_helper\0")).as_ptr(),
        116 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"pid=%ld\0" as *const u8 as *const libc::c_char,
        pid as libc::c_long,
    );
    *libc::__errno_location() = 0 as libc::c_int;
    while libc::waitpid(pid, &mut status, 0 as libc::c_int) == -(1 as libc::c_int) {
        if *libc::__errno_location() == 4 as libc::c_int {
            *libc::__errno_location() = 0 as libc::c_int;
        } else {
            oerrno = *libc::__errno_location();
            crate::log::sshlog(
                b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"reap_helper\0"))
                    .as_ptr(),
                125 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"libc::waitpid: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
            *libc::__errno_location() = oerrno;
            return -(24 as libc::c_int);
        }
    }
    if !(status & 0x7f as libc::c_int == 0 as libc::c_int) {
        crate::log::sshlog(
            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"reap_helper\0")).as_ptr(),
            130 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"helper exited abnormally\0" as *const u8 as *const libc::c_char,
        );
        return -(27 as libc::c_int);
    } else if (status & 0xff00 as libc::c_int) >> 8 as libc::c_int != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"reap_helper\0")).as_ptr(),
            133 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"helper exited with non-zero libc::exit status\0" as *const u8 as *const libc::c_char,
        );
        return -(27 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn client_converse(
    mut msg: *mut crate::sshbuf::sshbuf,
    mut respp: *mut *mut crate::sshbuf::sshbuf,
    mut type_0: u_int,
) -> libc::c_int {
    let mut oerrno: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut r2: libc::c_int = 0;
    let mut ll: libc::c_int = 0;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut rtype: u_int = 0;
    let mut rerr: u_int = 0;
    let mut pid: pid_t = 0;
    let mut version: u_char = 0;
    let mut osigchld: Option<unsafe extern "C" fn(libc::c_int) -> ()> = None;
    let mut req: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut resp: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    *respp = 0 as *mut crate::sshbuf::sshbuf;
    r = start_helper(&mut fd, &mut pid, &mut osigchld);
    if r != 0 as libc::c_int {
        return r;
    }
    req = crate::sshbuf::sshbuf_new();
    if req.is_null() || {
        resp = crate::sshbuf::sshbuf_new();
        resp.is_null()
    } {
        r = -(2 as libc::c_int);
    } else {
        ll = log_level_get() as libc::c_int;
        r = crate::sshbuf_getput_basic::sshbuf_put_u32(req, type_0);
        if r != 0 as libc::c_int
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(
                    req,
                    (log_is_on_stderr() != 0 as libc::c_int) as libc::c_int as u_char,
                );
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(
                    req,
                    (if ll < 0 as libc::c_int {
                        0 as libc::c_int
                    } else {
                        ll
                    }) as u_int32_t,
                );
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_putb(req, msg);
                r != 0 as libc::c_int
            }
        {
            crate::log::sshlog(
                b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"client_converse\0"))
                    .as_ptr(),
                163 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"compose\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = ssh_msg_send(fd, 5 as libc::c_int as u_char, req);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"client_converse\0",
                    ))
                    .as_ptr(),
                    167 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"send\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = ssh_msg_recv(fd, resp);
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"client_converse\0",
                        ))
                        .as_ptr(),
                        171 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"receive\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    r = crate::sshbuf_getput_basic::sshbuf_get_u8(resp, &mut version);
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"client_converse\0",
                            ))
                            .as_ptr(),
                            175 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"parse version\0" as *const u8 as *const libc::c_char,
                        );
                    } else if version as libc::c_int != 5 as libc::c_int {
                        crate::log::sshlog(
                            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"client_converse\0",
                            ))
                            .as_ptr(),
                            180 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"unsupported version: got %u, expected %u\0" as *const u8
                                as *const libc::c_char,
                            version as libc::c_int,
                            5 as libc::c_int,
                        );
                        r = -(4 as libc::c_int);
                    } else {
                        r = crate::sshbuf_getput_basic::sshbuf_get_u32(resp, &mut rtype);
                        if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                    b"client_converse\0",
                                ))
                                .as_ptr(),
                                185 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"parse message type\0" as *const u8 as *const libc::c_char,
                            );
                        } else if rtype == 0 as libc::c_int as libc::c_uint {
                            r = crate::sshbuf_getput_basic::sshbuf_get_u32(resp, &mut rerr);
                            if r != 0 as libc::c_int {
                                crate::log::sshlog(
                                    b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"client_converse\0",
                                    ))
                                    .as_ptr(),
                                    190 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    ssh_err(r),
                                    b"parse\0" as *const u8 as *const libc::c_char,
                                );
                            } else {
                                crate::log::sshlog(
                                    b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"client_converse\0",
                                    ))
                                    .as_ptr(),
                                    193 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG1,
                                    0 as *const libc::c_char,
                                    b"helper returned error -%u\0" as *const u8
                                        as *const libc::c_char,
                                    rerr,
                                );
                                if rerr == 0 as libc::c_int as libc::c_uint
                                    || rerr >= 2147483647 as libc::c_int as libc::c_uint
                                {
                                    r = -(1 as libc::c_int);
                                } else {
                                    r = -(rerr as libc::c_int);
                                }
                            }
                        } else if rtype != type_0 {
                            crate::log::sshlog(
                                b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                    b"client_converse\0",
                                ))
                                .as_ptr(),
                                202 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"helper returned incorrect message type %u, expecting %u\0"
                                    as *const u8
                                    as *const libc::c_char,
                                rtype,
                                type_0,
                            );
                            r = -(1 as libc::c_int);
                        } else {
                            r = 0 as libc::c_int;
                        }
                    }
                }
            }
        }
    }
    oerrno = *libc::__errno_location();
    close(fd);
    r2 = reap_helper(pid);
    if r2 != 0 as libc::c_int {
        if r == 0 as libc::c_int {
            r = r2;
            oerrno = *libc::__errno_location();
        }
    }
    if r == 0 as libc::c_int {
        *respp = resp;
        resp = 0 as *mut crate::sshbuf::sshbuf;
    }
    crate::sshbuf::sshbuf_free(req);
    crate::sshbuf::sshbuf_free(resp);
    crate::misc::ssh_signal(17 as libc::c_int, osigchld);
    *libc::__errno_location() = oerrno;
    return r;
}
pub unsafe extern "C" fn sshsk_sign(
    mut provider: *const libc::c_char,
    mut key: *mut crate::sshkey::sshkey,
    mut sigp: *mut *mut u_char,
    mut lenp: *mut size_t,
    mut data: *const u_char,
    mut datalen: size_t,
    mut compat: u_int,
    mut pin: *const libc::c_char,
) -> libc::c_int {
    let mut oerrno: libc::c_int = 0;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut kbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut req: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut resp: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    *sigp = 0 as *mut u_char;
    *lenp = 0 as libc::c_int as size_t;
    kbuf = crate::sshbuf::sshbuf_new();
    if kbuf.is_null() || {
        req = crate::sshbuf::sshbuf_new();
        req.is_null()
    } {
        r = -(2 as libc::c_int);
    } else {
        r = sshkey_private_serialize(key, kbuf);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sshsk_sign\0"))
                    .as_ptr(),
                251 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"encode key\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = sshbuf_put_stringb(req, kbuf);
            if r != 0 as libc::c_int
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_cstring(req, provider);
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_string(
                        req,
                        data as *const libc::c_void,
                        datalen,
                    );
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_cstring(
                        req,
                        0 as *const libc::c_char,
                    );
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(req, compat);
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_cstring(req, pin);
                    r != 0 as libc::c_int
                }
            {
                crate::log::sshlog(
                    b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"sshsk_sign\0"))
                        .as_ptr(),
                    260 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"compose\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = client_converse(req, &mut resp, 1 as libc::c_int as u_int);
                if !(r != 0 as libc::c_int) {
                    r = crate::sshbuf_getput_basic::sshbuf_get_string(resp, sigp, lenp);
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                b"sshsk_sign\0",
                            ))
                            .as_ptr(),
                            268 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"parse signature\0" as *const u8 as *const libc::c_char,
                        );
                        r = -(4 as libc::c_int);
                    } else if crate::sshbuf::sshbuf_len(resp) != 0 as libc::c_int as libc::c_ulong {
                        crate::log::sshlog(
                            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(
                                b"sshsk_sign\0",
                            ))
                            .as_ptr(),
                            273 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"trailing data in response\0" as *const u8 as *const libc::c_char,
                        );
                        r = -(4 as libc::c_int);
                    } else {
                        r = 0 as libc::c_int;
                    }
                }
            }
        }
    }
    oerrno = *libc::__errno_location();
    if r != 0 as libc::c_int {
        freezero(*sigp as *mut libc::c_void, *lenp);
        *sigp = 0 as *mut u_char;
        *lenp = 0 as libc::c_int as size_t;
    }
    crate::sshbuf::sshbuf_free(kbuf);
    crate::sshbuf::sshbuf_free(req);
    crate::sshbuf::sshbuf_free(resp);
    *libc::__errno_location() = oerrno;
    return r;
}
pub unsafe extern "C" fn sshsk_enroll(
    mut type_0: libc::c_int,
    mut provider_path: *const libc::c_char,
    mut device: *const libc::c_char,
    mut application: *const libc::c_char,
    mut userid: *const libc::c_char,
    mut flags: uint8_t,
    mut pin: *const libc::c_char,
    mut challenge_buf: *mut crate::sshbuf::sshbuf,
    mut keyp: *mut *mut crate::sshkey::sshkey,
    mut attest: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut oerrno: libc::c_int = 0;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut kbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut abuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut req: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut resp: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    *keyp = 0 as *mut crate::sshkey::sshkey;
    if !attest.is_null() {
        crate::sshbuf::sshbuf_reset(attest);
    }
    if type_0 < 0 as libc::c_int {
        return -(10 as libc::c_int);
    }
    abuf = crate::sshbuf::sshbuf_new();
    if abuf.is_null()
        || {
            kbuf = crate::sshbuf::sshbuf_new();
            kbuf.is_null()
        }
        || {
            req = crate::sshbuf::sshbuf_new();
            req.is_null()
        }
    {
        r = -(2 as libc::c_int);
    } else {
        r = crate::sshbuf_getput_basic::sshbuf_put_u32(req, type_0 as u_int);
        if r != 0 as libc::c_int
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(req, provider_path);
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(req, device);
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(req, application);
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(req, userid);
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u8(req, flags);
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(req, pin);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put_stringb(req, challenge_buf);
                r != 0 as libc::c_int
            }
        {
            crate::log::sshlog(
                b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sshsk_enroll\0"))
                    .as_ptr(),
                329 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"compose\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = client_converse(req, &mut resp, 2 as libc::c_int as u_int);
            if !(r != 0 as libc::c_int) {
                r = sshbuf_get_stringb(resp, kbuf);
                if r != 0 as libc::c_int || {
                    r = sshbuf_get_stringb(resp, abuf);
                    r != 0 as libc::c_int
                } {
                    crate::log::sshlog(
                        b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"sshsk_enroll\0",
                        ))
                        .as_ptr(),
                        338 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"parse\0" as *const u8 as *const libc::c_char,
                    );
                    r = -(4 as libc::c_int);
                } else if crate::sshbuf::sshbuf_len(resp) != 0 as libc::c_int as libc::c_ulong {
                    crate::log::sshlog(
                        b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"sshsk_enroll\0",
                        ))
                        .as_ptr(),
                        343 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"trailing data in response\0" as *const u8 as *const libc::c_char,
                    );
                    r = -(4 as libc::c_int);
                } else {
                    r = sshkey_private_deserialize(kbuf, &mut key);
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"sshsk_enroll\0",
                            ))
                            .as_ptr(),
                            348 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"encode\0" as *const u8 as *const libc::c_char,
                        );
                    } else if !attest.is_null() && {
                        r = sshbuf_putb(attest, abuf);
                        r != 0 as libc::c_int
                    } {
                        crate::log::sshlog(
                            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"sshsk_enroll\0",
                            ))
                            .as_ptr(),
                            352 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"encode attestation information\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        r = 0 as libc::c_int;
                        *keyp = key;
                        key = 0 as *mut crate::sshkey::sshkey;
                    }
                }
            }
        }
    }
    oerrno = *libc::__errno_location();
    crate::sshkey::sshkey_free(key);
    crate::sshbuf::sshbuf_free(kbuf);
    crate::sshbuf::sshbuf_free(abuf);
    crate::sshbuf::sshbuf_free(req);
    crate::sshbuf::sshbuf_free(resp);
    *libc::__errno_location() = oerrno;
    return r;
}
unsafe extern "C" fn sshsk_free_resident_key(mut srk: *mut sshsk_resident_key) {
    if srk.is_null() {
        return;
    }
    crate::sshkey::sshkey_free((*srk).key);
    freezero((*srk).user_id as *mut libc::c_void, (*srk).user_id_len);
    libc::free(srk as *mut libc::c_void);
}
pub unsafe extern "C" fn sshsk_free_resident_keys(
    mut srks: *mut *mut sshsk_resident_key,
    mut nsrks: size_t,
) {
    let mut i: size_t = 0;
    if srks.is_null() || nsrks == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    i = 0 as libc::c_int as size_t;
    while i < nsrks {
        sshsk_free_resident_key(*srks.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    libc::free(srks as *mut libc::c_void);
}
pub unsafe extern "C" fn sshsk_load_resident(
    mut provider_path: *const libc::c_char,
    mut device: *const libc::c_char,
    mut pin: *const libc::c_char,
    mut flags: u_int,
    mut srksp: *mut *mut *mut sshsk_resident_key,
    mut nsrksp: *mut size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut oerrno: libc::c_int = 0;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut kbuf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut req: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut resp: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut srk: *mut sshsk_resident_key = 0 as *mut sshsk_resident_key;
    let mut srks: *mut *mut sshsk_resident_key = 0 as *mut *mut sshsk_resident_key;
    let mut tmp: *mut *mut sshsk_resident_key = 0 as *mut *mut sshsk_resident_key;
    let mut userid: *mut u_char = 0 as *mut u_char;
    let mut userid_len: size_t = 0 as libc::c_int as size_t;
    let mut nsrks: size_t = 0 as libc::c_int as size_t;
    *srksp = 0 as *mut *mut sshsk_resident_key;
    *nsrksp = 0 as libc::c_int as size_t;
    kbuf = crate::sshbuf::sshbuf_new();
    if kbuf.is_null() || {
        req = crate::sshbuf::sshbuf_new();
        req.is_null()
    } {
        r = -(2 as libc::c_int);
    } else {
        r = crate::sshbuf_getput_basic::sshbuf_put_cstring(req, provider_path);
        if r != 0 as libc::c_int
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(req, device);
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_cstring(req, pin);
                r != 0 as libc::c_int
            }
            || {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(req, flags);
                r != 0 as libc::c_int
            }
        {
            crate::log::sshlog(
                b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"sshsk_load_resident\0",
                ))
                .as_ptr(),
                420 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"compose\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = client_converse(req, &mut resp, 3 as libc::c_int as u_int);
            if !(r != 0 as libc::c_int) {
                loop {
                    if !(crate::sshbuf::sshbuf_len(resp) != 0 as libc::c_int as libc::c_ulong) {
                        current_block = 17478428563724192186;
                        break;
                    }
                    r = sshbuf_get_stringb(resp, kbuf);
                    if r != 0 as libc::c_int
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_get_cstring(
                                resp,
                                0 as *mut *mut libc::c_char,
                                0 as *mut size_t,
                            );
                            r != 0 as libc::c_int
                        }
                        || {
                            r = crate::sshbuf_getput_basic::sshbuf_get_string(
                                resp,
                                &mut userid,
                                &mut userid_len,
                            );
                            r != 0 as libc::c_int
                        }
                    {
                        crate::log::sshlog(
                            b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                b"sshsk_load_resident\0",
                            ))
                            .as_ptr(),
                            432 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"parse\0" as *const u8 as *const libc::c_char,
                        );
                        r = -(4 as libc::c_int);
                        current_block = 18195178125133313560;
                        break;
                    } else {
                        r = sshkey_private_deserialize(kbuf, &mut key);
                        if r != 0 as libc::c_int {
                            crate::log::sshlog(
                                b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                    b"sshsk_load_resident\0",
                                ))
                                .as_ptr(),
                                437 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"decode key\0" as *const u8 as *const libc::c_char,
                            );
                            current_block = 18195178125133313560;
                            break;
                        } else {
                            srk = calloc(
                                1 as libc::c_int as libc::c_ulong,
                                ::core::mem::size_of::<sshsk_resident_key>() as libc::c_ulong,
                            ) as *mut sshsk_resident_key;
                            if srk.is_null() {
                                crate::log::sshlog(
                                    b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                        b"sshsk_load_resident\0",
                                    ))
                                    .as_ptr(),
                                    441 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"calloc failed\0" as *const u8 as *const libc::c_char,
                                );
                                current_block = 18195178125133313560;
                                break;
                            } else {
                                (*srk).key = key;
                                key = 0 as *mut crate::sshkey::sshkey;
                                (*srk).user_id = userid;
                                (*srk).user_id_len = userid_len;
                                userid = 0 as *mut u_char;
                                userid_len = 0 as libc::c_int as size_t;
                                tmp = recallocarray(
                                    srks as *mut libc::c_void,
                                    nsrks,
                                    nsrks.wrapping_add(1 as libc::c_int as libc::c_ulong),
                                    ::core::mem::size_of::<*mut sshsk_resident_key>()
                                        as libc::c_ulong,
                                )
                                    as *mut *mut sshsk_resident_key;
                                if tmp.is_null() {
                                    crate::log::sshlog(
                                        b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                            b"sshsk_load_resident\0",
                                        ))
                                        .as_ptr(),
                                        452 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"recallocarray keys failed\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                    current_block = 18195178125133313560;
                                    break;
                                } else {
                                    crate::log::sshlog(
                                        b"ssh-sk-client.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                            b"sshsk_load_resident\0",
                                        ))
                                        .as_ptr(),
                                        457 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG1,
                                        0 as *const libc::c_char,
                                        b"srks[%zu]: %s %s uidlen %zu\0" as *const u8
                                            as *const libc::c_char,
                                        nsrks,
                                        crate::sshkey::sshkey_type((*srk).key),
                                        (*(*srk).key).sk_application,
                                        (*srk).user_id_len,
                                    );
                                    srks = tmp;
                                    let fresh0 = nsrks;
                                    nsrks = nsrks.wrapping_add(1);
                                    let ref mut fresh1 = *srks.offset(fresh0 as isize);
                                    *fresh1 = srk;
                                    srk = 0 as *mut sshsk_resident_key;
                                }
                            }
                        }
                    }
                }
                match current_block {
                    18195178125133313560 => {}
                    _ => {
                        r = 0 as libc::c_int;
                        *srksp = srks;
                        *nsrksp = nsrks;
                        srks = 0 as *mut *mut sshsk_resident_key;
                        nsrks = 0 as libc::c_int as size_t;
                    }
                }
            }
        }
    }
    oerrno = *libc::__errno_location();
    sshsk_free_resident_key(srk);
    sshsk_free_resident_keys(srks, nsrks);
    freezero(userid as *mut libc::c_void, userid_len);
    crate::sshkey::sshkey_free(key);
    crate::sshbuf::sshbuf_free(kbuf);
    crate::sshbuf::sshbuf_free(req);
    crate::sshbuf::sshbuf_free(resp);
    *libc::__errno_location() = oerrno;
    return r;
}
