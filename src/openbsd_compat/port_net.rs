use ::c2rust_bitfields;
use ::libc;
extern "C" {
    pub type ssh;
    pub type sshbuf;
    fn socket(__domain: libc::c_int, __type: libc::c_int, __protocol: libc::c_int) -> libc::c_int;
    fn getsockopt(
        __fd: libc::c_int,
        __level: libc::c_int,
        __optname: libc::c_int,
        __optval: *mut libc::c_void,
        __optlen: *mut socklen_t,
    ) -> libc::c_int;
    fn setsockopt(
        __fd: libc::c_int,
        __level: libc::c_int,
        __optname: libc::c_int,
        __optval: *const libc::c_void,
        __optlen: socklen_t,
    ) -> libc::c_int;
    fn bzero(_: *mut libc::c_void, _: libc::c_ulong);
    fn __errno_location() -> *mut libc::c_int;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn ioctl(__fd: libc::c_int, __request: libc::c_ulong, _: ...) -> libc::c_int;
    fn open(__file: *const libc::c_char, __oflag: libc::c_int, _: ...) -> libc::c_int;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn sshlog(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
        _: LogLevel,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: ...
    );
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
    fn sshbuf_get_string(
        buf: *mut sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_string(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __time_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type socklen_t = __socklen_t;
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
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_addr_t = uint32_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct ip {
    #[bitfield(name = "ip_hl", ty = "libc::c_uint", bits = "0..=3")]
    #[bitfield(name = "ip_v", ty = "libc::c_uint", bits = "4..=7")]
    pub ip_hl_ip_v: [u8; 1],
    pub ip_tos: uint8_t,
    pub ip_len: libc::c_ushort,
    pub ip_id: libc::c_ushort,
    pub ip_off: libc::c_ushort,
    pub ip_ttl: uint8_t,
    pub ip_p: uint8_t,
    pub ip_sum: libc::c_ushort,
    pub ip_src: in_addr,
    pub ip_dst: in_addr,
}
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
    pub input: *mut sshbuf,
    pub output: *mut sshbuf,
    pub extended: *mut sshbuf,
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
    pub entry: C2RustUnnamed,
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
pub struct C2RustUnnamed {
    pub tqe_next: *mut channel_confirm,
    pub tqe_prev: *mut *mut channel_confirm,
}
pub type channel_callback_fn =
    unsafe extern "C" fn(*mut ssh, libc::c_int, libc::c_int, *mut libc::c_void) -> ();
pub type channel_open_fn =
    unsafe extern "C" fn(*mut ssh, libc::c_int, libc::c_int, *mut libc::c_void) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub ifrn_name: [libc::c_char; 16],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ifreq {
    pub ifr_ifrn: C2RustUnnamed_0,
    pub ifr_ifru: C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_1 {
    pub ifru_addr: sockaddr,
    pub ifru_dstaddr: sockaddr,
    pub ifru_broadaddr: sockaddr,
    pub ifru_netmask: sockaddr,
    pub ifru_hwaddr: sockaddr,
    pub ifru_flags: libc::c_short,
    pub ifru_ivalue: libc::c_int,
    pub ifru_mtu: libc::c_int,
    pub ifru_map: ifmap,
    pub ifru_slave: [libc::c_char; 16],
    pub ifru_newname: [libc::c_char; 16],
    pub ifru_data: *mut libc::c_void,
    pub ifru_settings: if_settings,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct if_settings {
    pub type_0: libc::c_uint,
    pub size: libc::c_uint,
    pub ifs_ifsu: C2RustUnnamed_2,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_2 {
    pub raw_hdlc: *mut raw_hdlc_proto,
    pub cisco: *mut cisco_proto,
    pub fr: *mut fr_proto,
    pub fr_pvc: *mut fr_proto_pvc,
    pub fr_pvc_info: *mut fr_proto_pvc_info,
    pub x25: *mut x25_hdlc_proto,
    pub sync: *mut sync_serial_settings,
    pub te1: *mut te1_settings,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct te1_settings {
    pub clock_rate: libc::c_uint,
    pub clock_type: libc::c_uint,
    pub loopback: libc::c_ushort,
    pub slot_map: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sync_serial_settings {
    pub clock_rate: libc::c_uint,
    pub clock_type: libc::c_uint,
    pub loopback: libc::c_ushort,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct x25_hdlc_proto {
    pub dce: libc::c_ushort,
    pub modulo: libc::c_uint,
    pub window: libc::c_uint,
    pub t1: libc::c_uint,
    pub t2: libc::c_uint,
    pub n2: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fr_proto_pvc_info {
    pub dlci: libc::c_uint,
    pub master: [libc::c_char; 16],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fr_proto_pvc {
    pub dlci: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct fr_proto {
    pub t391: libc::c_uint,
    pub t392: libc::c_uint,
    pub n391: libc::c_uint,
    pub n392: libc::c_uint,
    pub n393: libc::c_uint,
    pub lmi: libc::c_ushort,
    pub dce: libc::c_ushort,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct cisco_proto {
    pub interval: libc::c_uint,
    pub timeout: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct raw_hdlc_proto {
    pub encoding: libc::c_ushort,
    pub parity: libc::c_ushort,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ifmap {
    pub mem_start: libc::c_ulong,
    pub mem_end: libc::c_ulong,
    pub base_addr: libc::c_ushort,
    pub irq: libc::c_uchar,
    pub dma: libc::c_uchar,
    pub port: libc::c_uchar,
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
#[no_mangle]
pub unsafe extern "C" fn sys_get_rdomain(mut fd: libc::c_int) -> *mut libc::c_char {
    let mut dev: [libc::c_char; 17] = [0; 17];
    let mut len: socklen_t = (::core::mem::size_of::<[libc::c_char; 17]>() as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as socklen_t;
    if getsockopt(
        fd,
        1 as libc::c_int,
        25 as libc::c_int,
        dev.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    ) == -(1 as libc::c_int)
    {
        sshlog(
            b"port-net.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"sys_get_rdomain\0"))
                .as_ptr(),
            58 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s: cannot determine VRF for fd=%d : %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"sys_get_rdomain\0"))
                .as_ptr(),
            fd,
            strerror(*__errno_location()),
        );
        return 0 as *mut libc::c_char;
    }
    dev[len as usize] = '\0' as i32 as libc::c_char;
    return strdup(dev.as_mut_ptr());
}
#[no_mangle]
pub unsafe extern "C" fn sys_set_rdomain(
    mut fd: libc::c_int,
    mut name: *const libc::c_char,
) -> libc::c_int {
    if setsockopt(
        fd,
        1 as libc::c_int,
        25 as libc::c_int,
        name as *const libc::c_void,
        strlen(name) as socklen_t,
    ) == -(1 as libc::c_int)
    {
        sshlog(
            b"port-net.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"sys_set_rdomain\0"))
                .as_ptr(),
            71 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s: setsockopt(%d, SO_BINDTODEVICE, %s): %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"sys_set_rdomain\0"))
                .as_ptr(),
            fd,
            name,
            strerror(*__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn sys_valid_rdomain(mut name: *const libc::c_char) -> libc::c_int {
    let mut fd: libc::c_int = 0;
    fd = socket(
        2 as libc::c_int,
        SOCK_STREAM as libc::c_int,
        0 as libc::c_int,
    );
    if fd == -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    if setsockopt(
        fd,
        1 as libc::c_int,
        25 as libc::c_int,
        name as *const libc::c_void,
        strlen(name) as socklen_t,
    ) == -(1 as libc::c_int)
    {
        close(fd);
        return 0 as libc::c_int;
    }
    close(fd);
    return 1 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn sys_tun_open(
    mut tun: libc::c_int,
    mut mode: libc::c_int,
    mut ifname: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut ifr: ifreq = ifreq {
        ifr_ifrn: C2RustUnnamed_0 { ifrn_name: [0; 16] },
        ifr_ifru: C2RustUnnamed_1 {
            ifru_addr: sockaddr {
                sa_family: 0,
                sa_data: [0; 14],
            },
        },
    };
    let mut fd: libc::c_int = -(1 as libc::c_int);
    let mut name: *const libc::c_char = 0 as *const libc::c_char;
    if !ifname.is_null() {
        *ifname = 0 as *mut libc::c_char;
    }
    fd = open(
        b"/dev/net/tun\0" as *const u8 as *const libc::c_char,
        0o2 as libc::c_int,
    );
    if fd == -(1 as libc::c_int) {
        sshlog(
            b"port-net.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sys_tun_open\0")).as_ptr(),
            154 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"%s: failed to open tunnel control device \"%s\": %s\0" as *const u8
                as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sys_tun_open\0")).as_ptr(),
            b"/dev/net/tun\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    bzero(
        &mut ifr as *mut ifreq as *mut libc::c_void,
        ::core::mem::size_of::<ifreq>() as libc::c_ulong,
    );
    if mode == 0x2 as libc::c_int {
        ifr.ifr_ifru.ifru_flags = 0x2 as libc::c_int as libc::c_short;
        name = b"tap%d\0" as *const u8 as *const libc::c_char;
    } else {
        ifr.ifr_ifru.ifru_flags = 0x1 as libc::c_int as libc::c_short;
        name = b"tun%d\0" as *const u8 as *const libc::c_char;
    }
    ifr.ifr_ifru.ifru_flags =
        (ifr.ifr_ifru.ifru_flags as libc::c_int | 0x1000 as libc::c_int) as libc::c_short;
    if tun != 0x7fffffff as libc::c_int {
        if tun > 0x7fffffff as libc::c_int - 2 as libc::c_int {
            sshlog(
                b"port-net.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sys_tun_open\0"))
                    .as_ptr(),
                172 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"%s: invalid tunnel id %x: %s\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sys_tun_open\0"))
                    .as_ptr(),
                tun,
                strerror(*__errno_location()),
            );
            current_block = 3387529812613067600;
        } else {
            snprintf(
                (ifr.ifr_ifrn.ifrn_name).as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 16]>() as libc::c_ulong,
                name,
                tun,
            );
            current_block = 17407779659766490442;
        }
    } else {
        current_block = 17407779659766490442;
    }
    match current_block {
        17407779659766490442 => {
            if ioctl(
                fd,
                ((1 as libc::c_uint)
                    << 0 as libc::c_int + 8 as libc::c_int + 8 as libc::c_int + 14 as libc::c_int
                    | (('T' as i32) << 0 as libc::c_int + 8 as libc::c_int) as libc::c_uint
                    | ((202 as libc::c_int) << 0 as libc::c_int) as libc::c_uint)
                    as libc::c_ulong
                    | (::core::mem::size_of::<libc::c_int>() as libc::c_ulong)
                        << 0 as libc::c_int + 8 as libc::c_int + 8 as libc::c_int,
                &mut ifr as *mut ifreq,
            ) == -(1 as libc::c_int)
            {
                sshlog(
                    b"port-net.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sys_tun_open\0"))
                        .as_ptr(),
                    180 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"%s: failed to configure tunnel (mode %d): %s\0" as *const u8
                        as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sys_tun_open\0"))
                        .as_ptr(),
                    mode,
                    strerror(*__errno_location()),
                );
            } else {
                if tun == 0x7fffffff as libc::c_int {
                    sshlog(
                        b"port-net.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"sys_tun_open\0",
                        ))
                        .as_ptr(),
                        185 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"%s: tunnel mode %d fd %d\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"sys_tun_open\0",
                        ))
                        .as_ptr(),
                        mode,
                        fd,
                    );
                } else {
                    sshlog(
                        b"port-net.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"sys_tun_open\0",
                        ))
                        .as_ptr(),
                        187 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"%s: %s mode %d fd %d\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"sys_tun_open\0",
                        ))
                        .as_ptr(),
                        (ifr.ifr_ifrn.ifrn_name).as_mut_ptr(),
                        mode,
                        fd,
                    );
                }
                if !(!ifname.is_null() && {
                    *ifname = strdup((ifr.ifr_ifrn.ifrn_name).as_mut_ptr());
                    (*ifname).is_null()
                }) {
                    return fd;
                }
            }
        }
        _ => {}
    }
    close(fd);
    return -(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn sys_tun_infilter(
    mut ssh: *mut ssh,
    mut c: *mut Channel,
    mut buf: *mut libc::c_char,
    mut _len: libc::c_int,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut len: size_t = 0;
    let mut ptr: *mut libc::c_char = buf;
    let mut rbuf: [libc::c_char; 16384] = [0; 16384];
    let mut iph: ip = ip {
        ip_hl_ip_v: [0; 1],
        ip_tos: 0,
        ip_len: 0,
        ip_id: 0,
        ip_off: 0,
        ip_ttl: 0,
        ip_p: 0,
        ip_sum: 0,
        ip_src: in_addr { s_addr: 0 },
        ip_dst: in_addr { s_addr: 0 },
    };
    let mut af: u_int32_t = 0;
    if _len < 0 as libc::c_int {
        return -(1 as libc::c_int);
    }
    len = _len as size_t;
    if len <= ::core::mem::size_of::<ip>() as libc::c_ulong
        || len
            > (::core::mem::size_of::<[libc::c_char; 16384]>() as libc::c_ulong)
                .wrapping_sub(4 as libc::c_int as libc::c_ulong)
    {
        return -(1 as libc::c_int);
    }
    memcpy(
        &mut iph as *mut ip as *mut libc::c_void,
        buf as *const libc::c_void,
        ::core::mem::size_of::<ip>() as libc::c_ulong,
    );
    af = (if iph.ip_v() as libc::c_int == 6 as libc::c_int {
        24 as libc::c_int
    } else {
        2 as libc::c_int
    }) as u_int32_t;
    memcpy(
        rbuf.as_mut_ptr().offset(4 as libc::c_int as isize) as *mut libc::c_void,
        buf as *const libc::c_void,
        len,
    );
    len =
        (len as libc::c_ulong).wrapping_add(4 as libc::c_int as libc::c_ulong) as size_t as size_t;
    let __v: u_int32_t = af;
    *(rbuf.as_mut_ptr() as *mut u_char).offset(0 as libc::c_int as isize) =
        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *(rbuf.as_mut_ptr() as *mut u_char).offset(1 as libc::c_int as isize) =
        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *(rbuf.as_mut_ptr() as *mut u_char).offset(2 as libc::c_int as isize) =
        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
    *(rbuf.as_mut_ptr() as *mut u_char).offset(3 as libc::c_int as isize) =
        (__v & 0xff as libc::c_int as libc::c_uint) as u_char;
    ptr = rbuf.as_mut_ptr();
    r = sshbuf_put_string((*c).input, ptr as *const libc::c_void, len);
    if r != 0 as libc::c_int {
        sshfatal(
            b"port-net.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"sys_tun_infilter\0"))
                .as_ptr(),
            348 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: buffer error: %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"sys_tun_infilter\0"))
                .as_ptr(),
            ssh_err(r),
        );
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn sys_tun_outfilter(
    mut ssh: *mut ssh,
    mut c: *mut Channel,
    mut data: *mut *mut u_char,
    mut dlen: *mut size_t,
) -> *mut u_char {
    let mut buf: *mut u_char = 0 as *mut u_char;
    let mut af: u_int32_t = 0;
    let mut r: libc::c_int = 0;
    r = sshbuf_get_string((*c).output, data, dlen);
    if r != 0 as libc::c_int {
        sshfatal(
            b"port-net.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"sys_tun_outfilter\0"))
                .as_ptr(),
            362 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: buffer error: %s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"sys_tun_outfilter\0"))
                .as_ptr(),
            ssh_err(r),
        );
    }
    if *dlen < ::core::mem::size_of::<u_int32_t>() as libc::c_ulong {
        return 0 as *mut u_char;
    }
    buf = *data;
    *dlen = (*dlen as libc::c_ulong)
        .wrapping_sub(::core::mem::size_of::<u_int32_t>() as libc::c_ulong) as size_t
        as size_t;
    buf = (*data).offset(::core::mem::size_of::<u_int32_t>() as libc::c_ulong as isize);
    return buf;
}
