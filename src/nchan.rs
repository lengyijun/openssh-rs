use ::libc;
extern "C" {
    pub type ssh_channels;
    pub type sshkey;
    pub type kex;
    pub type session_state;

    fn shutdown(__fd: libc::c_int, __how: libc::c_int) -> libc::c_int;

    fn sshbuf_reset(buf: *mut crate::sshbuf::sshbuf);
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn sshpkt_send(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_start(ssh: *mut ssh, type_0: u_char) -> libc::c_int;
    fn sshpkt_put_cstring(ssh: *mut ssh, v: *const libc::c_void) -> libc::c_int;
    fn sshpkt_put_u8(ssh: *mut ssh, val: u_char) -> libc::c_int;
    fn sshpkt_put_u32(ssh: *mut ssh, val: u_int32_t) -> libc::c_int;
    fn channel_close_fd(_: *mut ssh, _: *mut Channel, _: *mut libc::c_int) -> libc::c_int;
    fn channel_format_extended_usage(_: *const Channel) -> *const libc::c_char;

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
pub type __uint32_t = libc::c_uint;
pub type __time_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type C2RustUnnamed = libc::c_uint;
pub const SHUT_RDWR: C2RustUnnamed = 2;
pub const SHUT_WR: C2RustUnnamed = 1;
pub const SHUT_RD: C2RustUnnamed = 0;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct addrinfo {
    pub ai_flags: libc::c_int,
    pub ai_family: libc::c_int,
    pub ai_socktype: libc::c_int,
    pub ai_protocol: libc::c_int,
    pub ai_addrlen: socklen_t,
    pub ai_addr: *mut sockaddr,
    pub ai_canonname: *mut libc::c_char,
    pub ai_next: *mut addrinfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Channel {
    pub type_0: libc::c_int,
    pub self_0: libc::c_int,
    pub remote_id: uint32_t,
    pub have_remote_id: libc::c_int,
    pub istate: u_int,
    pub ostate: u_int,
    pub flags: libc::c_int,
    pub rfd: libc::c_int,
    pub wfd: libc::c_int,
    pub efd: libc::c_int,
    pub sock: libc::c_int,
    pub io_want: u_int,
    pub io_ready: u_int,
    pub pfds: [libc::c_int; 4],
    pub ctl_chan: libc::c_int,
    pub isatty: libc::c_int,
    pub client_tty: libc::c_int,
    pub force_drain: libc::c_int,
    pub notbefore: time_t,
    pub delayed: libc::c_int,
    pub restore_block: libc::c_int,
    pub restore_flags: [libc::c_int; 3],
    pub input: *mut crate::sshbuf::sshbuf,
    pub output: *mut crate::sshbuf::sshbuf,
    pub extended: *mut crate::sshbuf::sshbuf,
    pub path: *mut libc::c_char,
    pub listening_port: libc::c_int,
    pub listening_addr: *mut libc::c_char,
    pub host_port: libc::c_int,
    pub remote_name: *mut libc::c_char,
    pub remote_window: u_int,
    pub remote_maxpacket: u_int,
    pub local_window: u_int,
    pub local_window_max: u_int,
    pub local_consumed: u_int,
    pub local_maxpacket: u_int,
    pub extended_usage: libc::c_int,
    pub single_connection: libc::c_int,
    pub ctype: *mut libc::c_char,
    pub xctype: *mut libc::c_char,
    pub open_confirm: Option<channel_open_fn>,
    pub open_confirm_ctx: *mut libc::c_void,
    pub detach_user: Option<channel_callback_fn>,
    pub detach_close: libc::c_int,
    pub status_confirms: channel_confirms,
    pub input_filter: Option<channel_infilter_fn>,
    pub output_filter: Option<channel_outfilter_fn>,
    pub filter_ctx: *mut libc::c_void,
    pub filter_cleanup: Option<channel_filter_cleanup_fn>,
    pub datagram: libc::c_int,
    pub connect_ctx: channel_connect,
    pub mux_rcb: Option<mux_callback_fn>,
    pub mux_ctx: *mut libc::c_void,
    pub mux_pause: libc::c_int,
    pub mux_downstream_id: libc::c_int,
    pub lastused: time_t,
    pub inactive_deadline: u_int,
}
pub type mux_callback_fn = unsafe extern "C" fn(*mut ssh, *mut Channel) -> libc::c_int;
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
    pub private_keys: C2RustUnnamed_2,
    pub public_keys: C2RustUnnamed_0,
    pub authctxt: *mut libc::c_void,
    pub chanctxt: *mut ssh_channels,
    pub app_data: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct key_entry {
    pub next: C2RustUnnamed_1,
    pub key: *mut sshkey,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub tqe_next: *mut key_entry,
    pub tqe_prev: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
pub type dispatch_fn = unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct channel_connect {
    pub host: *mut libc::c_char,
    pub port: libc::c_int,
    pub ai: *mut addrinfo,
    pub aitop: *mut addrinfo,
}
pub type channel_filter_cleanup_fn =
    unsafe extern "C" fn(*mut ssh, libc::c_int, *mut libc::c_void) -> ();
pub type channel_outfilter_fn =
    unsafe extern "C" fn(*mut ssh, *mut Channel, *mut *mut u_char, *mut size_t) -> *mut u_char;
pub type channel_infilter_fn =
    unsafe extern "C" fn(*mut ssh, *mut Channel, *mut libc::c_char, libc::c_int) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct channel_confirms {
    pub tqh_first: *mut channel_confirm,
    pub tqh_last: *mut *mut channel_confirm,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct channel_confirm {
    pub entry: C2RustUnnamed_3,
    pub cb: Option<channel_confirm_cb>,
    pub abandon_cb: Option<channel_confirm_abandon_cb>,
    pub ctx: *mut libc::c_void,
}
pub type channel_confirm_abandon_cb =
    unsafe extern "C" fn(*mut ssh, *mut Channel, *mut libc::c_void) -> ();
pub type channel_confirm_cb =
    unsafe extern "C" fn(*mut ssh, libc::c_int, *mut Channel, *mut libc::c_void) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_3 {
    pub tqe_next: *mut channel_confirm,
    pub tqe_prev: *mut *mut channel_confirm,
}
pub type channel_callback_fn =
    unsafe extern "C" fn(*mut ssh, libc::c_int, libc::c_int, *mut libc::c_void) -> ();
pub type channel_open_fn =
    unsafe extern "C" fn(*mut ssh, libc::c_int, libc::c_int, *mut libc::c_void) -> ();
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
static mut ostates: [*const libc::c_char; 4] = [
    b"open\0" as *const u8 as *const libc::c_char,
    b"drain\0" as *const u8 as *const libc::c_char,
    b"wait_ieof\0" as *const u8 as *const libc::c_char,
    b"closed\0" as *const u8 as *const libc::c_char,
];
static mut istates: [*const libc::c_char; 4] = [
    b"open\0" as *const u8 as *const libc::c_char,
    b"drain\0" as *const u8 as *const libc::c_char,
    b"wait_oclose\0" as *const u8 as *const libc::c_char,
    b"closed\0" as *const u8 as *const libc::c_char,
];
unsafe extern "C" fn chan_set_istate(mut c: *mut Channel, mut next: u_int) {
    if (*c).istate > 3 as libc::c_int as libc::c_uint || next > 3 as libc::c_int as libc::c_uint {
        sshfatal(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"chan_set_istate\0"))
                .as_ptr(),
            96 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"chan_set_istate: bad state %d -> %d\0" as *const u8 as *const libc::c_char,
            (*c).istate,
            next,
        );
    }
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"chan_set_istate\0")).as_ptr(),
        98 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: input %s -> %s\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        istates[(*c).istate as usize],
        istates[next as usize],
    );
    (*c).istate = next;
}
unsafe extern "C" fn chan_set_ostate(mut c: *mut Channel, mut next: u_int) {
    if (*c).ostate > 3 as libc::c_int as libc::c_uint || next > 3 as libc::c_int as libc::c_uint {
        sshfatal(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"chan_set_ostate\0"))
                .as_ptr(),
            106 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"chan_set_ostate: bad state %d -> %d\0" as *const u8 as *const libc::c_char,
            (*c).ostate,
            next,
        );
    }
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"chan_set_ostate\0")).as_ptr(),
        108 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: output %s -> %s\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        ostates[(*c).ostate as usize],
        ostates[next as usize],
    );
    (*c).ostate = next;
}
pub unsafe extern "C" fn chan_read_failed(mut ssh: *mut ssh, mut c: *mut Channel) {
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"chan_read_failed\0")).as_ptr(),
        115 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: read failed\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    match (*c).istate {
        0 => {
            chan_shutdown_read(ssh, c);
            chan_set_istate(c, 1 as libc::c_int as u_int);
        }
        _ => {
            crate::log::sshlog(
                b"nchan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"chan_read_failed\0"))
                    .as_ptr(),
                123 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"channel %d: chan_read_failed for istate %d\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
                (*c).istate,
            );
        }
    };
}
pub unsafe extern "C" fn chan_ibuf_empty(mut ssh: *mut ssh, mut c: *mut Channel) {
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"chan_ibuf_empty\0")).as_ptr(),
        131 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: ibuf empty\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    if crate::sshbuf::sshbuf_len((*c).input) != 0 {
        crate::log::sshlog(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"chan_ibuf_empty\0"))
                .as_ptr(),
            134 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"channel %d: chan_ibuf_empty for non empty buffer\0" as *const u8
                as *const libc::c_char,
            (*c).self_0,
        );
        return;
    }
    match (*c).istate {
        1 => {
            if (*c).flags & (0x1 as libc::c_int | 0x10 as libc::c_int) == 0 {
                chan_send_eof2(ssh, c);
            }
            chan_set_istate(c, 3 as libc::c_int as u_int);
        }
        _ => {
            crate::log::sshlog(
                b"nchan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"chan_ibuf_empty\0"))
                    .as_ptr(),
                145 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"channel %d: chan_ibuf_empty for istate %d\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
                (*c).istate,
            );
        }
    };
}
pub unsafe extern "C" fn chan_obuf_empty(mut ssh: *mut ssh, mut c: *mut Channel) {
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"chan_obuf_empty\0")).as_ptr(),
        153 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: obuf empty\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    if crate::sshbuf::sshbuf_len((*c).output) != 0 {
        crate::log::sshlog(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"chan_obuf_empty\0"))
                .as_ptr(),
            156 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"channel %d: chan_obuf_empty for non empty buffer\0" as *const u8
                as *const libc::c_char,
            (*c).self_0,
        );
        return;
    }
    match (*c).ostate {
        1 => {
            chan_shutdown_write(ssh, c);
            chan_set_ostate(c, 3 as libc::c_int as u_int);
        }
        _ => {
            crate::log::sshlog(
                b"nchan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"chan_obuf_empty\0"))
                    .as_ptr(),
                166 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"channel %d: internal error: obuf_empty for ostate %d\0" as *const u8
                    as *const libc::c_char,
                (*c).self_0,
                (*c).ostate,
            );
        }
    };
}
pub unsafe extern "C" fn chan_rcvd_eow(mut ssh: *mut ssh, mut c: *mut Channel) {
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"chan_rcvd_eow\0")).as_ptr(),
        174 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: rcvd eow\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    match (*c).istate {
        0 => {
            chan_shutdown_read(ssh, c);
            chan_set_istate(c, 3 as libc::c_int as u_int);
        }
        _ => {}
    };
}
unsafe extern "C" fn chan_send_eof2(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"chan_send_eof2\0")).as_ptr(),
        188 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: send eof\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    match (*c).istate {
        1 => {
            if (*c).have_remote_id == 0 {
                sshfatal(
                    b"nchan.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"chan_send_eof2\0",
                    ))
                    .as_ptr(),
                    192 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"channel %d: no remote_id\0" as *const u8 as *const libc::c_char,
                    (*c).self_0,
                );
            }
            r = sshpkt_start(ssh, 96 as libc::c_int as u_char);
            if r != 0 as libc::c_int
                || {
                    r = sshpkt_put_u32(ssh, (*c).remote_id);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_send(ssh);
                    r != 0 as libc::c_int
                }
            {
                sshfatal(
                    b"nchan.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"chan_send_eof2\0",
                    ))
                    .as_ptr(),
                    196 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"send CHANNEL_EOF\0" as *const u8 as *const libc::c_char,
                );
            }
            (*c).flags |= 0x4 as libc::c_int;
        }
        _ => {
            crate::log::sshlog(
                b"nchan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"chan_send_eof2\0"))
                    .as_ptr(),
                201 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"channel %d: cannot send eof for istate %d\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
                (*c).istate,
            );
        }
    };
}
unsafe extern "C" fn chan_send_close2(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"chan_send_close2\0")).as_ptr(),
        211 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: send close\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    if (*c).ostate != 3 as libc::c_int as libc::c_uint
        || (*c).istate != 3 as libc::c_int as libc::c_uint
    {
        crate::log::sshlog(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"chan_send_close2\0"))
                .as_ptr(),
            215 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"channel %d: cannot send close for istate/ostate %d/%d\0" as *const u8
                as *const libc::c_char,
            (*c).self_0,
            (*c).istate,
            (*c).ostate,
        );
    } else if (*c).flags & 0x1 as libc::c_int != 0 {
        crate::log::sshlog(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"chan_send_close2\0"))
                .as_ptr(),
            217 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"channel %d: already sent close\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    } else {
        if (*c).have_remote_id == 0 {
            sshfatal(
                b"nchan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"chan_send_close2\0"))
                    .as_ptr(),
                220 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"channel %d: no remote_id\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
        r = sshpkt_start(ssh, 97 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshpkt_put_u32(ssh, (*c).remote_id);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_send(ssh);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"nchan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"chan_send_close2\0"))
                    .as_ptr(),
                224 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"send CHANNEL_EOF\0" as *const u8 as *const libc::c_char,
            );
        }
        (*c).flags |= 0x1 as libc::c_int;
    };
}
unsafe extern "C" fn chan_send_eow2(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"chan_send_eow2\0")).as_ptr(),
        234 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: send eow\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    if (*c).ostate == 3 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"chan_send_eow2\0"))
                .as_ptr(),
            237 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"channel %d: must not sent eow on closed output\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        return;
    }
    if (*ssh).compat & 0x4000000 as libc::c_int == 0 {
        return;
    }
    if (*c).have_remote_id == 0 {
        sshfatal(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"chan_send_eow2\0"))
                .as_ptr(),
            243 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d: no remote_id\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    r = sshpkt_start(ssh, 98 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_u32(ssh, (*c).remote_id);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_cstring(
                ssh,
                b"eow@openssh.com\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u8(ssh, 0 as libc::c_int as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"chan_send_eow2\0"))
                .as_ptr(),
            249 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send CHANNEL_EOF\0" as *const u8 as *const libc::c_char,
        );
    }
}
pub unsafe extern "C" fn chan_rcvd_ieof(mut ssh: *mut ssh, mut c: *mut Channel) {
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"chan_rcvd_ieof\0")).as_ptr(),
        257 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: rcvd eof\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    (*c).flags |= 0x8 as libc::c_int;
    if (*c).ostate == 0 as libc::c_int as libc::c_uint {
        chan_set_ostate(c, 1 as libc::c_int as u_int);
    }
    if (*c).ostate == 1 as libc::c_int as libc::c_uint
        && crate::sshbuf::sshbuf_len((*c).output) == 0 as libc::c_int as libc::c_ulong
        && !((*c).extended_usage == 2 as libc::c_int
            && (*c).efd != -(1 as libc::c_int)
            && ((*c).flags & (0x8 as libc::c_int | 0x2 as libc::c_int) == 0
                || crate::sshbuf::sshbuf_len((*c).extended) > 0 as libc::c_int as libc::c_ulong))
    {
        chan_obuf_empty(ssh, c);
    }
}
pub unsafe extern "C" fn chan_rcvd_oclose(mut ssh: *mut ssh, mut c: *mut Channel) {
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"chan_rcvd_oclose\0")).as_ptr(),
        270 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: rcvd close\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    if (*c).flags & 0x10 as libc::c_int == 0 {
        if (*c).flags & 0x2 as libc::c_int != 0 {
            crate::log::sshlog(
                b"nchan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"chan_rcvd_oclose\0"))
                    .as_ptr(),
                274 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"channel %d: protocol error: close rcvd twice\0" as *const u8
                    as *const libc::c_char,
                (*c).self_0,
            );
        }
        (*c).flags |= 0x2 as libc::c_int;
    }
    if (*c).type_0 == 10 as libc::c_int {
        chan_set_ostate(c, 3 as libc::c_int as u_int);
        chan_set_istate(c, 3 as libc::c_int as u_int);
        return;
    }
    match (*c).ostate {
        0 => {
            chan_set_ostate(c, 1 as libc::c_int as u_int);
        }
        _ => {}
    }
    match (*c).istate {
        0 => {
            chan_shutdown_read(ssh, c);
            chan_shutdown_extended_read(ssh, c);
            chan_set_istate(c, 3 as libc::c_int as u_int);
        }
        1 => {
            if (*c).flags & 0x10 as libc::c_int == 0 {
                chan_send_eof2(ssh, c);
            }
            chan_shutdown_extended_read(ssh, c);
            chan_set_istate(c, 3 as libc::c_int as u_int);
        }
        _ => {}
    };
}
pub unsafe extern "C" fn chan_write_failed(mut ssh: *mut ssh, mut c: *mut Channel) {
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"chan_write_failed\0"))
            .as_ptr(),
        310 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: write failed\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    match (*c).ostate {
        0 | 1 => {
            chan_shutdown_write(ssh, c);
            if libc::strcmp((*c).ctype, b"session\0" as *const u8 as *const libc::c_char)
                == 0 as libc::c_int
            {
                chan_send_eow2(ssh, c);
            }
            chan_set_ostate(c, 3 as libc::c_int as u_int);
        }
        _ => {
            crate::log::sshlog(
                b"nchan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"chan_write_failed\0"))
                    .as_ptr(),
                321 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"channel %d: chan_write_failed for ostate %d\0" as *const u8
                    as *const libc::c_char,
                (*c).self_0,
                (*c).ostate,
            );
        }
    };
}
pub unsafe extern "C" fn chan_mark_dead(mut _ssh: *mut ssh, mut c: *mut Channel) {
    (*c).type_0 = 14 as libc::c_int;
}
pub unsafe extern "C" fn chan_is_dead(
    mut ssh: *mut ssh,
    mut c: *mut Channel,
    mut do_send: libc::c_int,
) -> libc::c_int {
    if (*c).type_0 == 14 as libc::c_int {
        crate::log::sshlog(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"chan_is_dead\0")).as_ptr(),
            336 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: zombie\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        return 1 as libc::c_int;
    }
    if (*c).istate != 3 as libc::c_int as libc::c_uint
        || (*c).ostate != 3 as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    if (*ssh).compat & 0x200000 as libc::c_int != 0
        && (*c).extended_usage == 2 as libc::c_int
        && (*c).efd != -(1 as libc::c_int)
        && crate::sshbuf::sshbuf_len((*c).extended) > 0 as libc::c_int as libc::c_ulong
    {
        crate::log::sshlog(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"chan_is_dead\0")).as_ptr(),
            346 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: active efd: %d len %zu\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            (*c).efd,
            crate::sshbuf::sshbuf_len((*c).extended),
        );
        return 0 as libc::c_int;
    }
    if (*c).flags & 0x10 as libc::c_int != 0 {
        crate::log::sshlog(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"chan_is_dead\0")).as_ptr(),
            350 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: is dead (local)\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        return 1 as libc::c_int;
    }
    if (*c).flags & 0x1 as libc::c_int == 0 {
        if do_send != 0 {
            chan_send_close2(ssh, c);
        } else if (*c).flags & 0x2 as libc::c_int != 0 {
            crate::log::sshlog(
                b"nchan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"chan_is_dead\0"))
                    .as_ptr(),
                360 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"channel %d: almost dead\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
            return 1 as libc::c_int;
        }
    }
    if (*c).flags & 0x1 as libc::c_int != 0 && (*c).flags & 0x2 as libc::c_int != 0 {
        crate::log::sshlog(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"chan_is_dead\0")).as_ptr(),
            367 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: is dead\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn chan_shutdown_write(mut ssh: *mut ssh, mut c: *mut Channel) {
    sshbuf_reset((*c).output);
    if (*c).type_0 == 10 as libc::c_int {
        return;
    }
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"chan_shutdown_write\0"))
            .as_ptr(),
        383 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: (i%d o%d sock %d wfd %d efd %d [%s])\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        (*c).istate,
        (*c).ostate,
        (*c).sock,
        (*c).wfd,
        (*c).efd,
        channel_format_extended_usage(c),
    );
    if (*c).sock != -(1 as libc::c_int) {
        if shutdown((*c).sock, SHUT_WR as libc::c_int) == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"nchan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"chan_shutdown_write\0",
                ))
                .as_ptr(),
                388 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"channel %d: shutdown() failed for fd %d [i%d o%d]: %.100s\0" as *const u8
                    as *const libc::c_char,
                (*c).self_0,
                (*c).sock,
                (*c).istate,
                (*c).ostate,
                libc::strerror(*libc::__errno_location()),
            );
        }
    } else if channel_close_fd(ssh, c, &mut (*c).wfd) < 0 as libc::c_int {
        crate::log::sshlog(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"chan_shutdown_write\0"))
                .as_ptr(),
            394 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"channel %d: close() failed for fd %d [i%d o%d]: %.100s\0" as *const u8
                as *const libc::c_char,
            (*c).self_0,
            (*c).wfd,
            (*c).istate,
            (*c).ostate,
            libc::strerror(*libc::__errno_location()),
        );
    }
}
unsafe extern "C" fn chan_shutdown_read(mut ssh: *mut ssh, mut c: *mut Channel) {
    if (*c).type_0 == 10 as libc::c_int {
        return;
    }
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"chan_shutdown_read\0"))
            .as_ptr(),
        406 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: (i%d o%d sock %d wfd %d efd %d [%s])\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        (*c).istate,
        (*c).ostate,
        (*c).sock,
        (*c).rfd,
        (*c).efd,
        channel_format_extended_usage(c),
    );
    if (*c).sock != -(1 as libc::c_int) {
        if shutdown((*c).sock, SHUT_RD as libc::c_int) == -(1 as libc::c_int)
            && *libc::__errno_location() != 107 as libc::c_int
        {
            crate::log::sshlog(
                b"nchan.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"chan_shutdown_read\0",
                ))
                .as_ptr(),
                416 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"channel %d: shutdown() failed for fd %d [i%d o%d]: %.100s\0" as *const u8
                    as *const libc::c_char,
                (*c).self_0,
                (*c).sock,
                (*c).istate,
                (*c).ostate,
                libc::strerror(*libc::__errno_location()),
            );
        }
    } else if channel_close_fd(ssh, c, &mut (*c).rfd) < 0 as libc::c_int {
        crate::log::sshlog(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"chan_shutdown_read\0"))
                .as_ptr(),
            422 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"channel %d: close() failed for fd %d [i%d o%d]: %.100s\0" as *const u8
                as *const libc::c_char,
            (*c).self_0,
            (*c).rfd,
            (*c).istate,
            (*c).ostate,
            libc::strerror(*libc::__errno_location()),
        );
    }
}
unsafe extern "C" fn chan_shutdown_extended_read(mut ssh: *mut ssh, mut c: *mut Channel) {
    if (*c).type_0 == 10 as libc::c_int || (*c).efd == -(1 as libc::c_int) {
        return;
    }
    if (*c).extended_usage != 1 as libc::c_int && (*c).extended_usage != 0 as libc::c_int {
        return;
    }
    crate::log::sshlog(
        b"nchan.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
            b"chan_shutdown_extended_read\0",
        ))
        .as_ptr(),
        437 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"channel %d: (i%d o%d sock %d wfd %d efd %d [%s])\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        (*c).istate,
        (*c).ostate,
        (*c).sock,
        (*c).rfd,
        (*c).efd,
        channel_format_extended_usage(c),
    );
    if channel_close_fd(ssh, c, &mut (*c).efd) < 0 as libc::c_int {
        crate::log::sshlog(
            b"nchan.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"chan_shutdown_extended_read\0",
            ))
            .as_ptr(),
            441 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"channel %d: close() failed for extended fd %d [i%d o%d]: %.100s\0" as *const u8
                as *const libc::c_char,
            (*c).self_0,
            (*c).efd,
            (*c).istate,
            (*c).ostate,
            libc::strerror(*libc::__errno_location()),
        );
    }
}
