use crate::packet::key_entry;

use crate::packet::ssh;
use ::libc;

extern "C" {

    fn freezero(_: *mut libc::c_void, _: size_t);

    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);

    fn userauth_finish(_: *mut ssh, _: libc::c_int, _: *const libc::c_char, _: *const libc::c_char);
    fn auth2_method_allowed(
        _: *mut Authctxt,
        _: *const libc::c_char,
        _: *const libc::c_char,
    ) -> libc::c_int;

    fn ssh_packet_write_wait(_: *mut ssh) -> libc::c_int;
    fn sshpkt_start(ssh: *mut ssh, type_0: u_char) -> libc::c_int;
    fn sshpkt_send(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_put_u8(ssh: *mut ssh, val: u_char) -> libc::c_int;
    fn sshpkt_put_u32(ssh: *mut ssh, val: u_int32_t) -> libc::c_int;
    fn sshpkt_put_cstring(ssh: *mut ssh, v: *const libc::c_void) -> libc::c_int;
    fn sshpkt_get_u32(ssh: *mut ssh, valp: *mut u_int32_t) -> libc::c_int;
    fn sshpkt_get_cstring(
        ssh: *mut ssh,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshpkt_get_end(ssh: *mut ssh) -> libc::c_int;
    fn ssh_dispatch_set(_: *mut ssh, _: libc::c_int, _: Option<dispatch_fn>);
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;

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
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type uint8_t = __uint8_t;

pub type sig_atomic_t = __sig_atomic_t;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub tqe_next: *mut key_entry,
    pub tqe_prev: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
pub type dispatch_fn = unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Authctxt {
    pub success: sig_atomic_t,
    pub authenticated: libc::c_int,
    pub postponed: libc::c_int,
    pub valid: libc::c_int,
    pub attempt: libc::c_int,
    pub failures: libc::c_int,
    pub server_caused_failure: libc::c_int,
    pub force_pwchange: libc::c_int,
    pub user: *mut libc::c_char,
    pub service: *mut libc::c_char,
    pub pw: *mut libc::passwd,
    pub style: *mut libc::c_char,
    pub auth_methods: *mut *mut libc::c_char,
    pub num_auth_methods: u_int,
    pub methoddata: *mut libc::c_void,
    pub kbdintctxt: *mut libc::c_void,
    pub loginmsg: *mut crate::sshbuf::sshbuf,
    pub prev_keys: *mut *mut crate::sshkey::sshkey,
    pub nprev_keys: u_int,
    pub auth_method_key: *mut crate::sshkey::sshkey,
    pub auth_method_info: *mut libc::c_char,
    pub session_info: *mut crate::sshbuf::sshbuf,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct KbdintDevice {
    pub name: *const libc::c_char,
    pub init_ctx: Option<unsafe extern "C" fn(*mut Authctxt) -> *mut libc::c_void>,
    pub query: Option<
        unsafe extern "C" fn(
            *mut libc::c_void,
            *mut *mut libc::c_char,
            *mut *mut libc::c_char,
            *mut u_int,
            *mut *mut *mut libc::c_char,
            *mut *mut u_int,
        ) -> libc::c_int,
    >,
    pub respond: Option<
        unsafe extern "C" fn(*mut libc::c_void, u_int, *mut *mut libc::c_char) -> libc::c_int,
    >,
    pub free_ctx: Option<unsafe extern "C" fn(*mut libc::c_void) -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct KbdintAuthctxt {
    pub devices: *mut libc::c_char,
    pub ctxt: *mut libc::c_void,
    pub device: *mut KbdintDevice,
    pub nreq: u_int,
    pub devices_done: u_int,
}
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
pub static mut devices: [*mut KbdintDevice; 1] = [0 as *const KbdintDevice as *mut KbdintDevice];
unsafe extern "C" fn kbdint_alloc(mut devs: *const libc::c_char) -> *mut KbdintAuthctxt {
    let mut kbdintctxt: *mut KbdintAuthctxt = 0 as *mut KbdintAuthctxt;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut i: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    kbdintctxt = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<KbdintAuthctxt>() as libc::c_ulong,
    ) as *mut KbdintAuthctxt;
    if libc::strcmp(devs, b"\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        b = crate::sshbuf::sshbuf_new();
        if b.is_null() {
            sshfatal(
                b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"kbdint_alloc\0"))
                    .as_ptr(),
                115 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                    as *const libc::c_char,
            );
        }
        i = 0 as libc::c_int;
        while !(devices[i as usize]).is_null() {
            r = crate::sshbuf_getput_basic::sshbuf_putf(
                b,
                b"%s%s\0" as *const u8 as *const libc::c_char,
                if crate::sshbuf::sshbuf_len(b) != 0 {
                    b",\0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                (*devices[i as usize]).name,
            );
            if r != 0 as libc::c_int {
                sshfatal(
                    b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"kbdint_alloc\0"))
                        .as_ptr(),
                    119 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"buffer error\0" as *const u8 as *const libc::c_char,
                );
            }
            i += 1;
            i;
        }
        (*kbdintctxt).devices = crate::sshbuf_misc::sshbuf_dup_string(b);
        if ((*kbdintctxt).devices).is_null() {
            sshfatal(
                b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"kbdint_alloc\0"))
                    .as_ptr(),
                122 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::sshbuf_misc::sshbuf_dup_string failed\0" as *const u8
                    as *const libc::c_char,
            );
        }
        crate::sshbuf::sshbuf_free(b);
    } else {
        (*kbdintctxt).devices = crate::xmalloc::xstrdup(devs);
    }
    crate::log::sshlog(
        b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"kbdint_alloc\0")).as_ptr(),
        127 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"kbdint_alloc: devices '%s'\0" as *const u8 as *const libc::c_char,
        (*kbdintctxt).devices,
    );
    (*kbdintctxt).ctxt = 0 as *mut libc::c_void;
    (*kbdintctxt).device = 0 as *mut KbdintDevice;
    (*kbdintctxt).nreq = 0 as libc::c_int as u_int;
    return kbdintctxt;
}
unsafe extern "C" fn kbdint_reset_device(mut kbdintctxt: *mut KbdintAuthctxt) {
    if !((*kbdintctxt).ctxt).is_null() {
        ((*(*kbdintctxt).device).free_ctx).expect("non-null function pointer")((*kbdintctxt).ctxt);
        (*kbdintctxt).ctxt = 0 as *mut libc::c_void;
    }
    (*kbdintctxt).device = 0 as *mut KbdintDevice;
}
unsafe extern "C" fn kbdint_free(mut kbdintctxt: *mut KbdintAuthctxt) {
    if !((*kbdintctxt).device).is_null() {
        kbdint_reset_device(kbdintctxt);
    }
    libc::free((*kbdintctxt).devices as *mut libc::c_void);
    freezero(
        kbdintctxt as *mut libc::c_void,
        ::core::mem::size_of::<KbdintAuthctxt>() as libc::c_ulong,
    );
}
unsafe extern "C" fn kbdint_next_device(
    mut authctxt: *mut Authctxt,
    mut kbdintctxt: *mut KbdintAuthctxt,
) -> libc::c_int {
    let mut len: size_t = 0;
    let mut t: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: libc::c_int = 0;
    if !((*kbdintctxt).device).is_null() {
        kbdint_reset_device(kbdintctxt);
    }
    loop {
        len = if !((*kbdintctxt).devices).is_null() {
            strcspn(
                (*kbdintctxt).devices,
                b",\0" as *const u8 as *const libc::c_char,
            )
        } else {
            0 as libc::c_int as libc::c_ulong
        };
        if len == 0 as libc::c_int as libc::c_ulong {
            break;
        }
        i = 0 as libc::c_int;
        while !(devices[i as usize]).is_null() {
            if !((*kbdintctxt).devices_done & ((1 as libc::c_int) << i) as libc::c_uint
                != 0 as libc::c_int as libc::c_uint
                || auth2_method_allowed(
                    authctxt,
                    b"keyboard-interactive\0" as *const u8 as *const libc::c_char,
                    (*devices[i as usize]).name,
                ) == 0)
            {
                if strncmp((*kbdintctxt).devices, (*devices[i as usize]).name, len)
                    == 0 as libc::c_int
                {
                    (*kbdintctxt).device = devices[i as usize];
                    (*kbdintctxt).devices_done |= ((1 as libc::c_int) << i) as libc::c_uint;
                }
            }
            i += 1;
            i;
        }
        t = (*kbdintctxt).devices;
        (*kbdintctxt).devices = if *t.offset(len as isize) as libc::c_int != 0 {
            crate::xmalloc::xstrdup(t.offset(len as isize).offset(1 as libc::c_int as isize))
        } else {
            0 as *mut libc::c_char
        };
        libc::free(t as *mut libc::c_void);
        crate::log::sshlog(
            b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"kbdint_next_device\0"))
                .as_ptr(),
            182 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"kbdint_next_device: devices %s\0" as *const u8 as *const libc::c_char,
            if !((*kbdintctxt).devices).is_null() {
                (*kbdintctxt).devices as *const libc::c_char
            } else {
                b"<empty>\0" as *const u8 as *const libc::c_char
            },
        );
        if !(!((*kbdintctxt).devices).is_null() && ((*kbdintctxt).device).is_null()) {
            break;
        }
    }
    return if !((*kbdintctxt).device).is_null() {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    };
}
pub unsafe extern "C" fn auth2_challenge(
    mut ssh: *mut ssh,
    mut devs: *mut libc::c_char,
) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    crate::log::sshlog(
        b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"auth2_challenge\0")).as_ptr(),
        198 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"auth2_challenge: user=%s devs=%s\0" as *const u8 as *const libc::c_char,
        if !((*authctxt).user).is_null() {
            (*authctxt).user as *const libc::c_char
        } else {
            b"<nouser>\0" as *const u8 as *const libc::c_char
        },
        if !devs.is_null() {
            devs as *const libc::c_char
        } else {
            b"<no devs>\0" as *const u8 as *const libc::c_char
        },
    );
    if ((*authctxt).user).is_null() || devs.is_null() {
        return 0 as libc::c_int;
    }
    if ((*authctxt).kbdintctxt).is_null() {
        (*authctxt).kbdintctxt = kbdint_alloc(devs) as *mut libc::c_void;
    }
    return auth2_challenge_start(ssh);
}
pub unsafe extern "C" fn auth2_challenge_stop(mut ssh: *mut ssh) {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    ssh_dispatch_set(ssh, 61 as libc::c_int, None);
    if !((*authctxt).kbdintctxt).is_null() {
        kbdint_free((*authctxt).kbdintctxt as *mut KbdintAuthctxt);
        (*authctxt).kbdintctxt = 0 as *mut libc::c_void;
    }
}
unsafe extern "C" fn auth2_challenge_start(mut ssh: *mut ssh) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut kbdintctxt: *mut KbdintAuthctxt = (*authctxt).kbdintctxt as *mut KbdintAuthctxt;
    crate::log::sshlog(
        b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth2_challenge_start\0"))
            .as_ptr(),
        228 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"auth2_challenge_start: devices %s\0" as *const u8 as *const libc::c_char,
        if !((*kbdintctxt).devices).is_null() {
            (*kbdintctxt).devices as *const libc::c_char
        } else {
            b"<empty>\0" as *const u8 as *const libc::c_char
        },
    );
    if kbdint_next_device(authctxt, kbdintctxt) == 0 as libc::c_int {
        auth2_challenge_stop(ssh);
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"auth2_challenge_start\0"))
            .as_ptr(),
        235 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"auth2_challenge_start: trying authentication method '%s'\0" as *const u8
            as *const libc::c_char,
        (*(*kbdintctxt).device).name,
    );
    (*kbdintctxt).ctxt =
        ((*(*kbdintctxt).device).init_ctx).expect("non-null function pointer")(authctxt);
    if ((*kbdintctxt).ctxt).is_null() {
        auth2_challenge_stop(ssh);
        return 0 as libc::c_int;
    }
    if send_userauth_info_request(ssh) == 0 as libc::c_int {
        auth2_challenge_stop(ssh);
        return 0 as libc::c_int;
    }
    ssh_dispatch_set(
        ssh,
        61 as libc::c_int,
        Some(
            input_userauth_info_response
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    (*authctxt).postponed = 1 as libc::c_int;
    return 0 as libc::c_int;
}
unsafe extern "C" fn send_userauth_info_request(mut ssh: *mut ssh) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut kbdintctxt: *mut KbdintAuthctxt = 0 as *mut KbdintAuthctxt;
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut instr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut prompts: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut r: u_int = 0;
    let mut i: u_int = 0;
    let mut echo_on: *mut u_int = 0 as *mut u_int;
    kbdintctxt = (*authctxt).kbdintctxt as *mut KbdintAuthctxt;
    if ((*(*kbdintctxt).device).query).expect("non-null function pointer")(
        (*kbdintctxt).ctxt,
        &mut name,
        &mut instr,
        &mut (*kbdintctxt).nreq,
        &mut prompts,
        &mut echo_on,
    ) != 0
    {
        return 0 as libc::c_int;
    }
    r = sshpkt_start(ssh, 60 as libc::c_int as u_char) as u_int;
    if r != 0 as libc::c_int as libc::c_uint
        || {
            r = sshpkt_put_cstring(ssh, name as *const libc::c_void) as u_int;
            r != 0 as libc::c_int as libc::c_uint
        }
        || {
            r = sshpkt_put_cstring(ssh, instr as *const libc::c_void) as u_int;
            r != 0 as libc::c_int as libc::c_uint
        }
        || {
            r = sshpkt_put_cstring(
                ssh,
                b"\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            ) as u_int;
            r != 0 as libc::c_int as libc::c_uint
        }
        || {
            r = sshpkt_put_u32(ssh, (*kbdintctxt).nreq) as u_int;
            r != 0 as libc::c_int as libc::c_uint
        }
    {
        sshfatal(
            b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"send_userauth_info_request\0",
            ))
            .as_ptr(),
            270 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r as libc::c_int),
            b"start packet\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int as u_int;
    while i < (*kbdintctxt).nreq {
        r = sshpkt_put_cstring(ssh, *prompts.offset(i as isize) as *const libc::c_void) as u_int;
        if r != 0 as libc::c_int as libc::c_uint || {
            r = sshpkt_put_u8(ssh, *echo_on.offset(i as isize) as u_char) as u_int;
            r != 0 as libc::c_int as libc::c_uint
        } {
            sshfatal(
                b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"send_userauth_info_request\0",
                ))
                .as_ptr(),
                274 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r as libc::c_int),
                b"assemble packet\0" as *const u8 as *const libc::c_char,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    r = sshpkt_send(ssh) as u_int;
    if r != 0 as libc::c_int as libc::c_uint || {
        r = ssh_packet_write_wait(ssh) as u_int;
        r != 0 as libc::c_int as libc::c_uint
    } {
        sshfatal(
            b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"send_userauth_info_request\0",
            ))
            .as_ptr(),
            278 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r as libc::c_int),
            b"send packet\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int as u_int;
    while i < (*kbdintctxt).nreq {
        libc::free(*prompts.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free(prompts as *mut libc::c_void);
    libc::free(echo_on as *mut libc::c_void);
    libc::free(name as *mut libc::c_void);
    libc::free(instr as *mut libc::c_void);
    return 1 as libc::c_int;
}
unsafe extern "C" fn input_userauth_info_response(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut authctxt: *mut Authctxt = (*ssh).authctxt as *mut Authctxt;
    let mut kbdintctxt: *mut KbdintAuthctxt = 0 as *mut KbdintAuthctxt;
    let mut authenticated: libc::c_int = 0 as libc::c_int;
    let mut res: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut i: u_int = 0;
    let mut nresp: u_int = 0;
    let mut devicename: *const libc::c_char = 0 as *const libc::c_char;
    let mut response: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    if authctxt.is_null() {
        sshfatal(
            b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"input_userauth_info_response\0",
            ))
            .as_ptr(),
            301 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no authctxt\0" as *const u8 as *const libc::c_char,
        );
    }
    kbdintctxt = (*authctxt).kbdintctxt as *mut KbdintAuthctxt;
    if kbdintctxt.is_null() || ((*kbdintctxt).ctxt).is_null() {
        sshfatal(
            b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"input_userauth_info_response\0",
            ))
            .as_ptr(),
            304 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no kbdintctxt\0" as *const u8 as *const libc::c_char,
        );
    }
    if ((*kbdintctxt).device).is_null() {
        sshfatal(
            b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"input_userauth_info_response\0",
            ))
            .as_ptr(),
            306 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no device\0" as *const u8 as *const libc::c_char,
        );
    }
    (*authctxt).postponed = 0 as libc::c_int;
    r = sshpkt_get_u32(ssh, &mut nresp);
    if r != 0 as libc::c_int {
        sshfatal(
            b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"input_userauth_info_response\0",
            ))
            .as_ptr(),
            310 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse packet\0" as *const u8 as *const libc::c_char,
        );
    }
    if nresp != (*kbdintctxt).nreq {
        sshfatal(
            b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"input_userauth_info_response\0",
            ))
            .as_ptr(),
            312 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"wrong number of replies\0" as *const u8 as *const libc::c_char,
        );
    }
    if nresp > 100 as libc::c_int as libc::c_uint {
        sshfatal(
            b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"input_userauth_info_response\0",
            ))
            .as_ptr(),
            314 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"too many replies\0" as *const u8 as *const libc::c_char,
        );
    }
    if nresp > 0 as libc::c_int as libc::c_uint {
        response = crate::xmalloc::xcalloc(
            nresp as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        ) as *mut *mut libc::c_char;
        i = 0 as libc::c_int as u_int;
        while i < nresp {
            r = sshpkt_get_cstring(ssh, &mut *response.offset(i as isize), 0 as *mut size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                        b"input_userauth_info_response\0",
                    ))
                    .as_ptr(),
                    319 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"parse response\0" as *const u8 as *const libc::c_char,
                );
            }
            i = i.wrapping_add(1);
            i;
        }
    }
    r = sshpkt_get_end(ssh);
    if r != 0 as libc::c_int {
        sshfatal(
            b"auth2-chall.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"input_userauth_info_response\0",
            ))
            .as_ptr(),
            323 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse packet\0" as *const u8 as *const libc::c_char,
        );
    }
    res = ((*(*kbdintctxt).device).respond).expect("non-null function pointer")(
        (*kbdintctxt).ctxt,
        nresp,
        response,
    );
    i = 0 as libc::c_int as u_int;
    while i < nresp {
        explicit_bzero(
            *response.offset(i as isize) as *mut libc::c_void,
            strlen(*response.offset(i as isize)),
        );
        libc::free(*response.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free(response as *mut libc::c_void);
    match res {
        0 => {
            authenticated = if (*authctxt).valid != 0 {
                1 as libc::c_int
            } else {
                0 as libc::c_int
            };
        }
        1 => {
            if send_userauth_info_request(ssh) == 1 as libc::c_int {
                (*authctxt).postponed = 1 as libc::c_int;
            }
        }
        _ => {}
    }
    devicename = (*(*kbdintctxt).device).name;
    if (*authctxt).postponed == 0 {
        if authenticated != 0 {
            auth2_challenge_stop(ssh);
        } else {
            auth2_challenge_start(ssh);
        }
    }
    userauth_finish(
        ssh,
        authenticated,
        b"keyboard-interactive\0" as *const u8 as *const libc::c_char,
        devicename,
    );
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn privsep_challenge_enable() {}
