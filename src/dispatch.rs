use ::libc;
extern "C" {
    pub type ssh_channels;
    pub type sshkey;
    pub type kex;
    pub type session_state;

    fn sshpkt_send(ssh: *mut ssh) -> libc::c_int;
    fn ssh_packet_read_seqnr(_: *mut ssh, _: *mut u_char, seqnr_p: *mut u_int32_t) -> libc::c_int;
    fn ssh_packet_read_poll_seqnr(
        _: *mut ssh,
        _: *mut u_char,
        seqnr_p: *mut u_int32_t,
    ) -> libc::c_int;
    fn sshpkt_disconnect(_: *mut ssh, fmt: *const libc::c_char, _: ...) -> libc::c_int;
    fn sshpkt_fatal(ssh: *mut ssh, r: libc::c_int, fmt: *const libc::c_char, _: ...) -> !;
    fn sshpkt_start(ssh: *mut ssh, type_0: u_char) -> libc::c_int;
    fn sshpkt_put_u32(ssh: *mut ssh, val: u_int32_t) -> libc::c_int;
    fn ssh_packet_write_wait(_: *mut ssh) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint32_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type u_int32_t = __uint32_t;
pub type sig_atomic_t = __sig_atomic_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh {
    pub state: *mut session_state,
    pub kex: *mut kex,
    pub remote_ipaddr: *mut libc::c_char,
    pub remote_port: libc::c_int,
    pub local_ipaddr: *mut libc::c_char,
    pub local_port: libc::c_int,
    pub rdomain_in: *mut libc::c_char,
    pub log_preamble: *mut libc::c_char,
    pub dispatch: [Option<dispatch_fn>; 255],
    pub dispatch_skip_packets: libc::c_int,
    pub compat: libc::c_int,
    pub private_keys: C2RustUnnamed_1,
    pub public_keys: C2RustUnnamed,
    pub authctxt: *mut libc::c_void,
    pub chanctxt: *mut ssh_channels,
    pub app_data: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct key_entry {
    pub next: C2RustUnnamed_0,
    pub key: *mut sshkey,
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
pub type C2RustUnnamed_2 = libc::c_uint;
pub const DISPATCH_NONBLOCK: C2RustUnnamed_2 = 1;
pub const DISPATCH_BLOCK: C2RustUnnamed_2 = 0;
pub unsafe extern "C" fn dispatch_protocol_error(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"dispatch.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"dispatch_protocol_error\0"))
            .as_ptr(),
        44 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"dispatch_protocol_error: type %d seq %u\0" as *const u8 as *const libc::c_char,
        type_0,
        seq,
    );
    r = sshpkt_start(ssh, 3 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_u32(ssh, seq);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
        || {
            r = ssh_packet_write_wait(ssh);
            r != 0 as libc::c_int
        }
    {
        sshpkt_fatal(
            ssh,
            r,
            b"%s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"dispatch_protocol_error\0",
            ))
            .as_ptr(),
        );
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn dispatch_protocol_ignore(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut _ssh: *mut ssh,
) -> libc::c_int {
    crate::log::sshlog(
        b"dispatch.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"dispatch_protocol_ignore\0"))
            .as_ptr(),
        56 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"dispatch_protocol_ignore: type %d seq %u\0" as *const u8 as *const libc::c_char,
        type_0,
        seq,
    );
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_dispatch_init(mut ssh: *mut ssh, mut dflt: Option<dispatch_fn>) {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < 255 as libc::c_int as libc::c_uint {
        (*ssh).dispatch[i as usize] = dflt;
        i = i.wrapping_add(1);
        i;
    }
}
pub unsafe extern "C" fn ssh_dispatch_range(
    mut ssh: *mut ssh,
    mut from: u_int,
    mut to: u_int,
    mut fn_0: Option<dispatch_fn>,
) {
    let mut i: u_int = 0;
    i = from;
    while i <= to {
        if i >= 255 as libc::c_int as libc::c_uint {
            break;
        }
        (*ssh).dispatch[i as usize] = fn_0;
        i = i.wrapping_add(1);
        i;
    }
}
pub unsafe extern "C" fn ssh_dispatch_set(
    mut ssh: *mut ssh,
    mut type_0: libc::c_int,
    mut fn_0: Option<dispatch_fn>,
) {
    (*ssh).dispatch[type_0 as usize] = fn_0;
}
pub unsafe extern "C" fn ssh_dispatch_run(
    mut ssh: *mut ssh,
    mut mode: libc::c_int,
    mut done: *mut sig_atomic_t,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut type_0: u_char = 0;
    let mut seqnr: u_int32_t = 0;
    loop {
        if mode == DISPATCH_BLOCK as libc::c_int {
            r = ssh_packet_read_seqnr(ssh, &mut type_0, &mut seqnr);
            if r != 0 as libc::c_int {
                return r;
            }
        } else {
            r = ssh_packet_read_poll_seqnr(ssh, &mut type_0, &mut seqnr);
            if r != 0 as libc::c_int {
                return r;
            }
            if type_0 as libc::c_int == 0 as libc::c_int {
                return 0 as libc::c_int;
            }
        }
        if type_0 as libc::c_int > 0 as libc::c_int
            && (type_0 as libc::c_int) < 255 as libc::c_int
            && ((*ssh).dispatch[type_0 as usize]).is_some()
        {
            if (*ssh).dispatch_skip_packets != 0 {
                crate::log::sshlog(
                    b"dispatch.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                        b"ssh_dispatch_run\0",
                    ))
                    .as_ptr(),
                    108 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"skipped packet (type %u)\0" as *const u8 as *const libc::c_char,
                    type_0 as libc::c_int,
                );
                (*ssh).dispatch_skip_packets -= 1;
                (*ssh).dispatch_skip_packets;
            } else {
                r = (Some(
                    (*((*ssh).dispatch).as_mut_ptr().offset(type_0 as isize))
                        .expect("non-null function pointer"),
                ))
                .expect("non-null function pointer")(
                    type_0 as libc::c_int, seqnr, ssh
                );
                if r != 0 as libc::c_int {
                    return r;
                }
                if !done.is_null() && *done != 0 {
                    return 0 as libc::c_int;
                }
            }
        } else {
            r = sshpkt_disconnect(
                ssh,
                b"protocol error: rcvd type %d\0" as *const u8 as *const libc::c_char,
                type_0 as libc::c_int,
            );
            if r != 0 as libc::c_int {
                return r;
            }
            return -(29 as libc::c_int);
        }
    }
}
pub unsafe extern "C" fn ssh_dispatch_run_fatal(
    mut ssh: *mut ssh,
    mut mode: libc::c_int,
    mut done: *mut sig_atomic_t,
) {
    let mut r: libc::c_int = 0;
    r = ssh_dispatch_run(ssh, mode, done);
    if r != 0 as libc::c_int {
        sshpkt_fatal(
            ssh,
            r,
            b"%s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"ssh_dispatch_run_fatal\0",
            ))
            .as_ptr(),
        );
    }
}
