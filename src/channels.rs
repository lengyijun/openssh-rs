use ::libc;
extern "C" {
    pub type sockaddr_x25;
    pub type sockaddr_ns;
    pub type sockaddr_iso;
    pub type sockaddr_ipx;
    pub type sockaddr_inarp;
    pub type sockaddr_eon;
    pub type sockaddr_dl;
    pub type sockaddr_ax25;
    pub type sockaddr_at;
    pub type sshbuf;
    pub type ec_key_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type kex;
    pub type session_state;
    fn socket(__domain: libc::c_int, __type: libc::c_int, __protocol: libc::c_int) -> libc::c_int;
    fn bind(__fd: libc::c_int, __addr: __CONST_SOCKADDR_ARG, __len: socklen_t) -> libc::c_int;
    fn connect(__fd: libc::c_int, __addr: __CONST_SOCKADDR_ARG, __len: socklen_t) -> libc::c_int;
    fn getsockopt(
        __fd: libc::c_int,
        __level: libc::c_int,
        __optname: libc::c_int,
        __optval: *mut libc::c_void,
        __optlen: *mut socklen_t,
    ) -> libc::c_int;
    fn listen(__fd: libc::c_int, __n: libc::c_int) -> libc::c_int;
    fn accept(__fd: libc::c_int, __addr: __SOCKADDR_ARG, __addr_len: *mut socklen_t)
        -> libc::c_int;
    fn tcgetattr(__fd: libc::c_int, __termios_p: *mut termios) -> libc::c_int;
    fn umask(__mask: __mode_t) -> __mode_t;
    fn __errno_location() -> *mut libc::c_int;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn getuid() -> __uid_t;
    fn isatty(__fd: libc::c_int) -> libc::c_int;
    fn arc4random_buf(_: *mut libc::c_void, _: size_t);
    fn getaddrinfo(
        __name: *const libc::c_char,
        __service: *const libc::c_char,
        __req: *const addrinfo,
        __pai: *mut *mut addrinfo,
    ) -> libc::c_int;
    fn freeaddrinfo(__ai: *mut addrinfo);
    fn getnameinfo(
        __sa: *const sockaddr,
        __salen: socklen_t,
        __host: *mut libc::c_char,
        __hostlen: socklen_t,
        __serv: *mut libc::c_char,
        __servlen: socklen_t,
        __flags: libc::c_int,
    ) -> libc::c_int;
    fn snprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn getpeereid(_: libc::c_int, _: *mut uid_t, _: *mut gid_t) -> libc::c_int;
    fn strtonum(
        _: *const libc::c_char,
        _: libc::c_longlong,
        _: libc::c_longlong,
        _: *mut *const libc::c_char,
    ) -> libc::c_longlong;
    fn timingsafe_bcmp(_: *const libc::c_void, _: *const libc::c_void, _: size_t) -> libc::c_int;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn ioctl(__fd: libc::c_int, __request: libc::c_ulong, _: ...) -> libc::c_int;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;
    fn memchr(_: *const libc::c_void, _: libc::c_int, _: libc::c_ulong) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strrchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn inet_ntoa(__in: in_addr) -> *mut libc::c_char;
    fn inet_ntop(
        __af: libc::c_int,
        __cp: *const libc::c_void,
        __buf: *mut libc::c_char,
        __len: socklen_t,
    ) -> *const libc::c_char;
    fn fcntl(__fd: libc::c_int, __cmd: libc::c_int, _: ...) -> libc::c_int;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn xmalloc(_: size_t) -> *mut libc::c_void;
    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn xrecallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn xasprintf(_: *mut *mut libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn sshbuf_read(_: libc::c_int, _: *mut sshbuf, _: size_t, _: *mut size_t) -> libc::c_int;
    fn sshbuf_dup_string(buf: *mut sshbuf) -> *mut libc::c_char;
    fn sshbuf_get_string_direct(
        buf: *mut sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_stringb(buf: *mut sshbuf, v: *const sshbuf) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_string(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_string(
        buf: *mut sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_u8(buf: *mut sshbuf, val: u_char) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_putf(buf: *mut sshbuf, fmt: *const libc::c_char, _: ...) -> libc::c_int;
    fn sshbuf_putb(buf: *mut sshbuf, v: *const sshbuf) -> libc::c_int;
    fn sshbuf_put(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_get(buf: *mut sshbuf, v: *mut libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_consume(buf: *mut sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_check_reserve(buf: *const sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_mutable_ptr(buf: *const sshbuf) -> *mut u_char;
    fn sshbuf_ptr(buf: *const sshbuf) -> *const u_char;
    fn sshbuf_avail(buf: *const sshbuf) -> size_t;
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_set_max_size(buf: *mut sshbuf, max_size: size_t) -> libc::c_int;
    fn sshbuf_reset(buf: *mut sshbuf);
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_from(blob: *const libc::c_void, len: size_t) -> *mut sshbuf;
    fn sshbuf_new() -> *mut sshbuf;
    fn ssh_packet_is_rekeying(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_log_type(_: u_char) -> libc::c_int;
    fn sshpkt_msg_ignore(_: *mut ssh, _: u_int) -> libc::c_int;
    fn sshpkt_put(ssh: *mut ssh, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshpkt_putb(ssh: *mut ssh, b: *const sshbuf) -> libc::c_int;
    fn sshpkt_put_u8(ssh: *mut ssh, val: u_char) -> libc::c_int;
    fn sshpkt_put_u32(ssh: *mut ssh, val: u_int32_t) -> libc::c_int;
    fn sshpkt_put_string(ssh: *mut ssh, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshpkt_put_cstring(ssh: *mut ssh, v: *const libc::c_void) -> libc::c_int;
    fn sshpkt_put_stringb(ssh: *mut ssh, v: *const sshbuf) -> libc::c_int;
    fn sshpkt_get_u32(ssh: *mut ssh, valp: *mut u_int32_t) -> libc::c_int;
    fn sshpkt_get_string_direct(
        ssh: *mut ssh,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshpkt_get_cstring(
        ssh: *mut ssh,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshpkt_get_end(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_ptr(_: *mut ssh, lenp: *mut size_t) -> *const u_char;
    fn sshpkt_send(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_start(ssh: *mut ssh, type_0: u_char) -> libc::c_int;
    fn ssh_remote_port(_: *mut ssh) -> libc::c_int;
    fn ssh_remote_ipaddr(_: *mut ssh) -> *const libc::c_char;
    fn ssh_packet_disconnect(_: *mut ssh, fmt: *const libc::c_char, _: ...) -> !;
    fn ssh_packet_send_debug(_: *mut ssh, fmt: *const libc::c_char, _: ...);
    fn ssh_packet_write_wait(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_set_alive_timeouts(_: *mut ssh, _: libc::c_int);
    fn ssh_packet_get_maxsize(_: *mut ssh) -> u_int;
    fn log_level_get() -> LogLevel;
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
    fn set_nonblock(_: libc::c_int) -> libc::c_int;
    fn set_nodelay(_: libc::c_int);
    fn set_reuseaddr(_: libc::c_int) -> libc::c_int;
    fn a2port(_: *const libc::c_char) -> libc::c_int;
    fn tohex(_: *const libc::c_void, _: size_t) -> *mut libc::c_char;
    fn monotime() -> time_t;
    fn lowercase(s: *mut libc::c_char);
    fn unix_listener(_: *const libc::c_char, _: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn sock_set_v6only(_: libc::c_int);
    fn ssh_gai_strerror(_: libc::c_int) -> *const libc::c_char;
    fn ptimeout_deadline_monotime(pt: *mut timespec, when: time_t);
    fn chan_is_dead(_: *mut ssh, _: *mut Channel, _: libc::c_int) -> libc::c_int;
    fn chan_mark_dead(_: *mut ssh, _: *mut Channel);
    fn chan_rcvd_oclose(_: *mut ssh, _: *mut Channel);
    fn chan_read_failed(_: *mut ssh, _: *mut Channel);
    fn chan_ibuf_empty(_: *mut ssh, _: *mut Channel);
    fn chan_rcvd_ieof(_: *mut ssh, _: *mut Channel);
    fn chan_write_failed(_: *mut ssh, _: *mut Channel);
    fn chan_obuf_empty(_: *mut ssh, _: *mut Channel);
    fn get_peer_ipaddr(_: libc::c_int) -> *mut libc::c_char;
    fn get_peer_port(_: libc::c_int) -> libc::c_int;
    fn get_local_ipaddr(_: libc::c_int) -> *mut libc::c_char;
    fn get_local_port(_: libc::c_int) -> libc::c_int;
    fn match_pattern(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_short = libc::c_ushort;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __mode_t = libc::c_uint;
pub type __time_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type u_char = __u_char;
pub type u_short = __u_short;
pub type u_int = __u_int;
pub type gid_t = __gid_t;
pub type mode_t = __mode_t;
pub type uid_t = __uid_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type u_int8_t = __uint8_t;
pub type u_int16_t = __uint16_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_storage {
    pub ss_family: sa_family_t,
    pub __ss_padding: [libc::c_char; 118],
    pub __ss_align: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union __SOCKADDR_ARG {
    pub __sockaddr__: *mut sockaddr,
    pub __sockaddr_at__: *mut sockaddr_at,
    pub __sockaddr_ax25__: *mut sockaddr_ax25,
    pub __sockaddr_dl__: *mut sockaddr_dl,
    pub __sockaddr_eon__: *mut sockaddr_eon,
    pub __sockaddr_in__: *mut sockaddr_in,
    pub __sockaddr_in6__: *mut sockaddr_in6,
    pub __sockaddr_inarp__: *mut sockaddr_inarp,
    pub __sockaddr_ipx__: *mut sockaddr_ipx,
    pub __sockaddr_iso__: *mut sockaddr_iso,
    pub __sockaddr_ns__: *mut sockaddr_ns,
    pub __sockaddr_un__: *mut sockaddr_un,
    pub __sockaddr_x25__: *mut sockaddr_x25,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_un {
    pub sun_family: sa_family_t,
    pub sun_path: [libc::c_char; 108],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
}
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
pub type uint16_t = __uint16_t;
pub type uint8_t = __uint8_t;
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_addr_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub union __CONST_SOCKADDR_ARG {
    pub __sockaddr__: *const sockaddr,
    pub __sockaddr_at__: *const sockaddr_at,
    pub __sockaddr_ax25__: *const sockaddr_ax25,
    pub __sockaddr_dl__: *const sockaddr_dl,
    pub __sockaddr_eon__: *const sockaddr_eon,
    pub __sockaddr_in__: *const sockaddr_in,
    pub __sockaddr_in6__: *const sockaddr_in6,
    pub __sockaddr_inarp__: *const sockaddr_inarp,
    pub __sockaddr_ipx__: *const sockaddr_ipx,
    pub __sockaddr_iso__: *const sockaddr_iso,
    pub __sockaddr_ns__: *const sockaddr_ns,
    pub __sockaddr_un__: *const sockaddr_un,
    pub __sockaddr_x25__: *const sockaddr_x25,
}
pub type cc_t = libc::c_uchar;
pub type speed_t = libc::c_uint;
pub type tcflag_t = libc::c_uint;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; 32],
    pub c_ispeed: speed_t,
    pub c_ospeed: speed_t,
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
pub struct pollfd {
    pub fd: libc::c_int,
    pub events: libc::c_short,
    pub revents: libc::c_short,
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
pub struct ssh_channels {
    pub channels: *mut *mut Channel,
    pub channels_alloc: u_int,
    pub channel_pre: *mut Option<chan_fn>,
    pub channel_post: *mut Option<chan_fn>,
    pub local_perms: permission_set,
    pub remote_perms: permission_set,
    pub x11_saved_display: *mut libc::c_char,
    pub x11_saved_proto: *mut libc::c_char,
    pub x11_saved_data: *mut libc::c_char,
    pub x11_saved_data_len: u_int,
    pub x11_refuse_time: time_t,
    pub x11_fake_data: *mut u_char,
    pub x11_fake_data_len: u_int,
    pub IPv4or6: libc::c_int,
    pub timeouts: *mut ssh_channel_timeout,
    pub ntimeouts: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh_channel_timeout {
    pub type_pattern: *mut libc::c_char,
    pub timeout_secs: u_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct permission_set {
    pub num_permitted_user: u_int,
    pub permitted_user: *mut permission,
    pub num_permitted_admin: u_int,
    pub permitted_admin: *mut permission,
    pub all_permitted: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct permission {
    pub host_to_connect: *mut libc::c_char,
    pub port_to_connect: libc::c_int,
    pub listen_host: *mut libc::c_char,
    pub listen_path: *mut libc::c_char,
    pub listen_port: libc::c_int,
    pub downstream: *mut Channel,
}
pub type chan_fn = unsafe extern "C" fn(*mut ssh, *mut Channel) -> ();
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
pub struct sshkey {
    pub type_0: libc::c_int,
    pub flags: libc::c_int,
    pub rsa: *mut RSA,
    pub dsa: *mut DSA,
    pub ecdsa_nid: libc::c_int,
    pub ecdsa: *mut EC_KEY,
    pub ed25519_sk: *mut u_char,
    pub ed25519_pk: *mut u_char,
    pub xmss_name: *mut libc::c_char,
    pub xmss_filename: *mut libc::c_char,
    pub xmss_state: *mut libc::c_void,
    pub xmss_sk: *mut u_char,
    pub xmss_pk: *mut u_char,
    pub sk_application: *mut libc::c_char,
    pub sk_flags: uint8_t,
    pub sk_key_handle: *mut sshbuf,
    pub sk_reserved: *mut sshbuf,
    pub cert: *mut sshkey_cert,
    pub shielded_private: *mut u_char,
    pub shielded_len: size_t,
    pub shield_prekey: *mut u_char,
    pub shield_prekey_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_cert {
    pub certblob: *mut sshbuf,
    pub type_0: u_int,
    pub serial: u_int64_t,
    pub key_id: *mut libc::c_char,
    pub nprincipals: u_int,
    pub principals: *mut *mut libc::c_char,
    pub valid_after: u_int64_t,
    pub valid_before: u_int64_t,
    pub critical: *mut sshbuf,
    pub extensions: *mut sshbuf,
    pub signature_key: *mut sshkey,
    pub signature_type: *mut libc::c_char,
}
pub type EC_KEY = ec_key_st;
pub type DSA = dsa_st;
pub type RSA = rsa_st;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct winsize {
    pub ws_row: libc::c_ushort,
    pub ws_col: libc::c_ushort,
    pub ws_xpixel: libc::c_ushort,
    pub ws_ypixel: libc::c_ushort,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Forward {
    pub listen_host: *mut libc::c_char,
    pub listen_port: libc::c_int,
    pub listen_path: *mut libc::c_char,
    pub connect_host: *mut libc::c_char,
    pub connect_port: libc::c_int,
    pub connect_path: *mut libc::c_char,
    pub allocated_port: libc::c_int,
    pub handle: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ForwardOptions {
    pub gateway_ports: libc::c_int,
    pub streamlocal_bind_mask: mode_t,
    pub streamlocal_bind_unlink: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_4 {
    pub version: u_int8_t,
    pub command: u_int8_t,
    pub reserved: u_int8_t,
    pub atyp: u_int8_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_5 {
    pub version: u_int8_t,
    pub command: u_int8_t,
    pub dest_port: u_int16_t,
    pub dest_addr: in_addr,
}
pub const CHAN_PRE: channel_table = 0;
pub const CHAN_POST: channel_table = 1;
pub type channel_table = libc::c_uint;
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
        | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
        as __uint16_t;
}
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
}
pub unsafe extern "C" fn channel_init_channels(mut ssh: *mut ssh) {
    let mut sc: *mut ssh_channels = 0 as *mut ssh_channels;
    sc = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<ssh_channels>() as libc::c_ulong,
    ) as *mut ssh_channels;
    if sc.is_null() {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_init_channels\0"))
                .as_ptr(),
            240 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"allocation failed\0" as *const u8 as *const libc::c_char,
        );
    }
    (*sc).channels_alloc = 10 as libc::c_int as u_int;
    (*sc).channels = xcalloc(
        (*sc).channels_alloc as size_t,
        ::core::mem::size_of::<*mut Channel>() as libc::c_ulong,
    ) as *mut *mut Channel;
    (*sc).IPv4or6 = 0 as libc::c_int;
    channel_handler_init(sc);
    (*ssh).chanctxt = sc;
}
pub unsafe extern "C" fn channel_by_id(mut ssh: *mut ssh, mut id: libc::c_int) -> *mut Channel {
    let mut c: *mut Channel = 0 as *mut Channel;
    if id < 0 as libc::c_int || id as u_int >= (*(*ssh).chanctxt).channels_alloc {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"channel_by_id\0"))
                .as_ptr(),
            255 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%d: bad id\0" as *const u8 as *const libc::c_char,
            id,
        );
        return 0 as *mut Channel;
    }
    c = *((*(*ssh).chanctxt).channels).offset(id as isize);
    if c.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"channel_by_id\0"))
                .as_ptr(),
            260 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%d: bad id: channel free\0" as *const u8 as *const libc::c_char,
            id,
        );
        return 0 as *mut Channel;
    }
    return c;
}
pub unsafe extern "C" fn channel_by_remote_id(
    mut ssh: *mut ssh,
    mut remote_id: u_int,
) -> *mut Channel {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < (*(*ssh).chanctxt).channels_alloc {
        c = *((*(*ssh).chanctxt).channels).offset(i as isize);
        if !c.is_null() && (*c).have_remote_id != 0 && (*c).remote_id == remote_id {
            return c;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *mut Channel;
}
pub unsafe extern "C" fn channel_lookup(mut ssh: *mut ssh, mut id: libc::c_int) -> *mut Channel {
    let mut c: *mut Channel = 0 as *mut Channel;
    c = channel_by_id(ssh, id);
    if c.is_null() {
        return 0 as *mut Channel;
    }
    match (*c).type_0 {
        7 | 10 | 12 | 13 | 21 | 22 | 3 | 4 | 17 | 20 => return c,
        _ => {}
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"channel_lookup\0")).as_ptr(),
        305 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"Non-public channel %d, type %d.\0" as *const u8 as *const libc::c_char,
        id,
        (*c).type_0,
    );
    return 0 as *mut Channel;
}
pub unsafe extern "C" fn channel_add_timeout(
    mut ssh: *mut ssh,
    mut type_pattern: *const libc::c_char,
    mut timeout_secs: u_int,
) {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"channel_add_timeout\0"))
            .as_ptr(),
        320 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel type \"%s\" timeout %u seconds\0" as *const u8 as *const libc::c_char,
        type_pattern,
        timeout_secs,
    );
    (*sc).timeouts = xrecallocarray(
        (*sc).timeouts as *mut libc::c_void,
        (*sc).ntimeouts,
        ((*sc).ntimeouts).wrapping_add(1 as libc::c_int as libc::c_ulong),
        ::core::mem::size_of::<ssh_channel_timeout>() as libc::c_ulong,
    ) as *mut ssh_channel_timeout;
    let ref mut fresh0 = (*((*sc).timeouts).offset((*sc).ntimeouts as isize)).type_pattern;
    *fresh0 = xstrdup(type_pattern);
    (*((*sc).timeouts).offset((*sc).ntimeouts as isize)).timeout_secs = timeout_secs;
    (*sc).ntimeouts = ((*sc).ntimeouts).wrapping_add(1);
    (*sc).ntimeouts;
}
pub unsafe extern "C" fn channel_clear_timeouts(mut ssh: *mut ssh) {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut i: size_t = 0;
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"channel_clear_timeouts\0"))
            .as_ptr(),
        335 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"clearing\0" as *const u8 as *const libc::c_char,
    );
    i = 0 as libc::c_int as size_t;
    while i < (*sc).ntimeouts {
        free((*((*sc).timeouts).offset(i as isize)).type_pattern as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    free((*sc).timeouts as *mut libc::c_void);
    (*sc).timeouts = 0 as *mut ssh_channel_timeout;
    (*sc).ntimeouts = 0 as libc::c_int as size_t;
}
unsafe extern "C" fn lookup_timeout(mut ssh: *mut ssh, mut type_0: *const libc::c_char) -> u_int {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < (*sc).ntimeouts {
        if match_pattern(type_0, (*((*sc).timeouts).offset(i as isize)).type_pattern) != 0 {
            return (*((*sc).timeouts).offset(i as isize)).timeout_secs;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int as u_int;
}
pub unsafe extern "C" fn channel_set_xtype(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut xctype: *const libc::c_char,
) {
    let mut c: *mut Channel = 0 as *mut Channel;
    c = channel_by_id(ssh, id);
    if c.is_null() {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"channel_set_xtype\0"))
                .as_ptr(),
            369 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"missing channel %d\0" as *const u8 as *const libc::c_char,
            id,
        );
    }
    if !((*c).xctype).is_null() {
        free((*c).xctype as *mut libc::c_void);
    }
    (*c).xctype = xstrdup(xctype);
    (*c).inactive_deadline = lookup_timeout(ssh, (*c).xctype);
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"channel_set_xtype\0"))
            .as_ptr(),
        376 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"labeled channel %d as %s (inactive timeout %u)\0" as *const u8 as *const libc::c_char,
        id,
        xctype,
        (*c).inactive_deadline,
    );
}
unsafe extern "C" fn channel_register_fds(
    mut _ssh: *mut ssh,
    mut c: *mut Channel,
    mut rfd: libc::c_int,
    mut wfd: libc::c_int,
    mut efd: libc::c_int,
    mut extusage: libc::c_int,
    mut nonblock: libc::c_int,
    mut is_tty: libc::c_int,
) {
    let mut val: libc::c_int = 0;
    if rfd != -(1 as libc::c_int) {
        fcntl(rfd, 2 as libc::c_int, 1 as libc::c_int);
    }
    if wfd != -(1 as libc::c_int) && wfd != rfd {
        fcntl(wfd, 2 as libc::c_int, 1 as libc::c_int);
    }
    if efd != -(1 as libc::c_int) && efd != rfd && efd != wfd {
        fcntl(efd, 2 as libc::c_int, 1 as libc::c_int);
    }
    (*c).rfd = rfd;
    (*c).wfd = wfd;
    (*c).sock = if rfd == wfd { rfd } else { -(1 as libc::c_int) };
    (*c).efd = efd;
    (*c).extended_usage = extusage;
    (*c).isatty = is_tty;
    if (*c).isatty != 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"channel_register_fds\0"))
                .as_ptr(),
            403 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: rfd %d isatty\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            (*c).rfd,
        );
    }
    (*c).restore_block = 0 as libc::c_int;
    if nonblock == 2 as libc::c_int {
        if rfd != -(1 as libc::c_int)
            && isatty(rfd) == 0
            && {
                val = fcntl(rfd, 3 as libc::c_int);
                val != -(1 as libc::c_int)
            }
            && val & 0o4000 as libc::c_int == 0
        {
            (*c).restore_flags[0 as libc::c_int as usize] = val;
            (*c).restore_block |= 0x1 as libc::c_int;
            set_nonblock(rfd);
        }
        if wfd != -(1 as libc::c_int)
            && isatty(wfd) == 0
            && {
                val = fcntl(wfd, 3 as libc::c_int);
                val != -(1 as libc::c_int)
            }
            && val & 0o4000 as libc::c_int == 0
        {
            (*c).restore_flags[1 as libc::c_int as usize] = val;
            (*c).restore_block |= 0x2 as libc::c_int;
            set_nonblock(wfd);
        }
        if efd != -(1 as libc::c_int)
            && isatty(efd) == 0
            && {
                val = fcntl(efd, 3 as libc::c_int);
                val != -(1 as libc::c_int)
            }
            && val & 0o4000 as libc::c_int == 0
        {
            (*c).restore_flags[2 as libc::c_int as usize] = val;
            (*c).restore_block |= 0x4 as libc::c_int;
            set_nonblock(efd);
        }
    } else if nonblock != 0 {
        if rfd != -(1 as libc::c_int) {
            set_nonblock(rfd);
        }
        if wfd != -(1 as libc::c_int) {
            set_nonblock(wfd);
        }
        if efd != -(1 as libc::c_int) {
            set_nonblock(efd);
        }
    }
}
pub unsafe extern "C" fn channel_new(
    mut ssh: *mut ssh,
    mut ctype: *mut libc::c_char,
    mut type_0: libc::c_int,
    mut rfd: libc::c_int,
    mut wfd: libc::c_int,
    mut efd: libc::c_int,
    mut window: u_int,
    mut maxpack: u_int,
    mut extusage: libc::c_int,
    mut remote_name: *const libc::c_char,
    mut nonblock: libc::c_int,
) -> *mut Channel {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut i: u_int = 0;
    let mut found: u_int = 0 as libc::c_int as u_int;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut r: libc::c_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < (*sc).channels_alloc {
        if (*((*sc).channels).offset(i as isize)).is_null() {
            found = i;
            break;
        } else {
            i = i.wrapping_add(1);
            i;
        }
    }
    if i >= (*sc).channels_alloc {
        found = (*sc).channels_alloc;
        if (*sc).channels_alloc > (16 as libc::c_int * 1024 as libc::c_int) as libc::c_uint {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"channel_new\0"))
                    .as_ptr(),
                475 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"internal error: channels_alloc %d too big\0" as *const u8 as *const libc::c_char,
                (*sc).channels_alloc,
            );
        }
        (*sc).channels = xrecallocarray(
            (*sc).channels as *mut libc::c_void,
            (*sc).channels_alloc as size_t,
            ((*sc).channels_alloc).wrapping_add(10 as libc::c_int as libc::c_uint) as size_t,
            ::core::mem::size_of::<*mut Channel>() as libc::c_ulong,
        ) as *mut *mut Channel;
        (*sc).channels_alloc = ((*sc).channels_alloc as libc::c_uint)
            .wrapping_add(10 as libc::c_int as libc::c_uint) as u_int
            as u_int;
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"channel_new\0")).as_ptr(),
            479 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel: expanding %d\0" as *const u8 as *const libc::c_char,
            (*sc).channels_alloc,
        );
    }
    let ref mut fresh1 = *((*sc).channels).offset(found as isize);
    *fresh1 = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<Channel>() as libc::c_ulong,
    ) as *mut Channel;
    c = *fresh1;
    (*c).input = sshbuf_new();
    if ((*c).input).is_null()
        || {
            (*c).output = sshbuf_new();
            ((*c).output).is_null()
        }
        || {
            (*c).extended = sshbuf_new();
            ((*c).extended).is_null()
        }
    {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"channel_new\0")).as_ptr(),
            486 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_set_max_size(
        (*c).input,
        (16 as libc::c_int * 1024 as libc::c_int * 1024 as libc::c_int) as size_t,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"channel_new\0")).as_ptr(),
            488 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"sshbuf_set_max_size\0" as *const u8 as *const libc::c_char,
        );
    }
    (*c).ostate = 0 as libc::c_int as u_int;
    (*c).istate = 0 as libc::c_int as u_int;
    channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, 0 as libc::c_int);
    (*c).self_0 = found as libc::c_int;
    (*c).type_0 = type_0;
    (*c).ctype = ctype;
    (*c).local_window = window;
    (*c).local_window_max = window;
    (*c).local_maxpacket = maxpack;
    (*c).remote_name = xstrdup(remote_name);
    (*c).ctl_chan = -(1 as libc::c_int);
    (*c).delayed = 1 as libc::c_int;
    (*c).inactive_deadline = lookup_timeout(ssh, (*c).ctype);
    (*c).status_confirms.tqh_first = 0 as *mut channel_confirm;
    (*c).status_confirms.tqh_last = &mut (*c).status_confirms.tqh_first;
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"channel_new\0")).as_ptr(),
        504 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"channel %d: new %s [%s] (inactive timeout: %u)\0" as *const u8 as *const libc::c_char,
        found,
        (*c).ctype,
        remote_name,
        (*c).inactive_deadline,
    );
    return c;
}
pub unsafe extern "C" fn channel_close_fd(
    mut _ssh: *mut ssh,
    mut c: *mut Channel,
    mut fdp: *mut libc::c_int,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    let mut fd: libc::c_int = *fdp;
    if fd == -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    if *fdp == (*c).rfd && (*c).restore_block & 0x1 as libc::c_int != 0 as libc::c_int {
        fcntl(
            *fdp,
            4 as libc::c_int,
            (*c).restore_flags[0 as libc::c_int as usize],
        );
    } else if *fdp == (*c).wfd && (*c).restore_block & 0x2 as libc::c_int != 0 as libc::c_int {
        fcntl(
            *fdp,
            4 as libc::c_int,
            (*c).restore_flags[1 as libc::c_int as usize],
        );
    } else if *fdp == (*c).efd && (*c).restore_block & 0x4 as libc::c_int != 0 as libc::c_int {
        fcntl(
            *fdp,
            4 as libc::c_int,
            (*c).restore_flags[2 as libc::c_int as usize],
        );
    }
    if *fdp == (*c).rfd {
        (*c).io_want &= !(0x1 as libc::c_int) as libc::c_uint;
        (*c).io_ready &= !(0x1 as libc::c_int) as libc::c_uint;
        (*c).rfd = -(1 as libc::c_int);
        (*c).pfds[0 as libc::c_int as usize] = -(1 as libc::c_int);
    }
    if *fdp == (*c).wfd {
        (*c).io_want &= !(0x2 as libc::c_int) as libc::c_uint;
        (*c).io_ready &= !(0x2 as libc::c_int) as libc::c_uint;
        (*c).wfd = -(1 as libc::c_int);
        (*c).pfds[1 as libc::c_int as usize] = -(1 as libc::c_int);
    }
    if *fdp == (*c).efd {
        (*c).io_want &= !(0x4 as libc::c_int | 0x8 as libc::c_int) as libc::c_uint;
        (*c).io_ready &= !(0x4 as libc::c_int | 0x8 as libc::c_int) as libc::c_uint;
        (*c).efd = -(1 as libc::c_int);
        (*c).pfds[2 as libc::c_int as usize] = -(1 as libc::c_int);
    }
    if *fdp == (*c).sock {
        (*c).io_want &= !(0x10 as libc::c_int | 0x20 as libc::c_int) as libc::c_uint;
        (*c).io_ready &= !(0x10 as libc::c_int | 0x20 as libc::c_int) as libc::c_uint;
        (*c).sock = -(1 as libc::c_int);
        (*c).pfds[3 as libc::c_int as usize] = -(1 as libc::c_int);
    }
    ret = close(fd);
    *fdp = -(1 as libc::c_int);
    return ret;
}
unsafe extern "C" fn channel_close_fds(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut sock: libc::c_int = (*c).sock;
    let mut rfd: libc::c_int = (*c).rfd;
    let mut wfd: libc::c_int = (*c).wfd;
    let mut efd: libc::c_int = (*c).efd;
    channel_close_fd(ssh, c, &mut (*c).sock);
    if rfd != sock {
        channel_close_fd(ssh, c, &mut (*c).rfd);
    }
    if wfd != sock && wfd != rfd {
        channel_close_fd(ssh, c, &mut (*c).wfd);
    }
    if efd != sock && efd != rfd && efd != wfd {
        channel_close_fd(ssh, c, &mut (*c).efd);
    }
}
unsafe extern "C" fn fwd_perm_clear(mut perm: *mut permission) {
    free((*perm).host_to_connect as *mut libc::c_void);
    free((*perm).listen_host as *mut libc::c_void);
    free((*perm).listen_path as *mut libc::c_void);
    memset(
        perm as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<permission>() as libc::c_ulong,
    );
}
unsafe extern "C" fn fwd_ident(
    mut who: libc::c_int,
    mut where_0: libc::c_int,
) -> *const libc::c_char {
    if who == 0x100 as libc::c_int {
        if where_0 == (1 as libc::c_int) << 1 as libc::c_int {
            return b"admin local\0" as *const u8 as *const libc::c_char;
        } else if where_0 == 1 as libc::c_int {
            return b"admin remote\0" as *const u8 as *const libc::c_char;
        }
    } else if who == 0x101 as libc::c_int {
        if where_0 == (1 as libc::c_int) << 1 as libc::c_int {
            return b"user local\0" as *const u8 as *const libc::c_char;
        } else if where_0 == 1 as libc::c_int {
            return b"user remote\0" as *const u8 as *const libc::c_char;
        }
    }
    sshfatal(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"fwd_ident\0")).as_ptr(),
        596 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_FATAL,
        0 as *const libc::c_char,
        b"Unknown forward permission list %d/%d\0" as *const u8 as *const libc::c_char,
        who,
        where_0,
    );
}
unsafe extern "C" fn permission_set_get(
    mut ssh: *mut ssh,
    mut where_0: libc::c_int,
) -> *mut permission_set {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    match where_0 {
        2 => return &mut (*sc).local_perms,
        1 => return &mut (*sc).remote_perms,
        _ => {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"permission_set_get\0",
                ))
                .as_ptr(),
                613 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"invalid forwarding direction %d\0" as *const u8 as *const libc::c_char,
                where_0,
            );
        }
    };
}
unsafe extern "C" fn permission_set_get_array(
    mut ssh: *mut ssh,
    mut who: libc::c_int,
    mut where_0: libc::c_int,
    mut permpp: *mut *mut *mut permission,
    mut npermpp: *mut *mut u_int,
) {
    let mut pset: *mut permission_set = permission_set_get(ssh, where_0);
    match who {
        257 => {
            *permpp = &mut (*pset).permitted_user;
            *npermpp = &mut (*pset).num_permitted_user;
        }
        256 => {
            *permpp = &mut (*pset).permitted_admin;
            *npermpp = &mut (*pset).num_permitted_admin;
        }
        _ => {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"permission_set_get_array\0",
                ))
                .as_ptr(),
                634 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"invalid forwarding client %d\0" as *const u8 as *const libc::c_char,
                who,
            );
        }
    };
}
unsafe extern "C" fn permission_set_add(
    mut ssh: *mut ssh,
    mut who: libc::c_int,
    mut where_0: libc::c_int,
    mut host_to_connect: *const libc::c_char,
    mut port_to_connect: libc::c_int,
    mut listen_host: *const libc::c_char,
    mut listen_path: *const libc::c_char,
    mut listen_port: libc::c_int,
    mut downstream: *mut Channel,
) -> libc::c_int {
    let mut permp: *mut *mut permission = 0 as *mut *mut permission;
    let mut n: u_int = 0;
    let mut npermp: *mut u_int = 0 as *mut u_int;
    permission_set_get_array(ssh, who, where_0, &mut permp, &mut npermp);
    if *npermp >= 2147483647 as libc::c_int as libc::c_uint {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"permission_set_add\0"))
                .as_ptr(),
            651 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s overflow\0" as *const u8 as *const libc::c_char,
            fwd_ident(who, where_0),
        );
    }
    *permp = xrecallocarray(
        *permp as *mut libc::c_void,
        *npermp as size_t,
        (*npermp).wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
        ::core::mem::size_of::<permission>() as libc::c_ulong,
    ) as *mut permission;
    let fresh2 = *npermp;
    *npermp = (*npermp).wrapping_add(1);
    n = fresh2;
    let ref mut fresh3 = (*(*permp).offset(n as isize)).host_to_connect;
    *fresh3 = if host_to_connect.is_null() {
        0 as *mut libc::c_char
    } else {
        xstrdup(host_to_connect)
    };
    (*(*permp).offset(n as isize)).port_to_connect = port_to_connect;
    let ref mut fresh4 = (*(*permp).offset(n as isize)).listen_host;
    *fresh4 = if listen_host.is_null() {
        0 as *mut libc::c_char
    } else {
        xstrdup(listen_host)
    };
    let ref mut fresh5 = (*(*permp).offset(n as isize)).listen_path;
    *fresh5 = if listen_path.is_null() {
        0 as *mut libc::c_char
    } else {
        xstrdup(listen_path)
    };
    (*(*permp).offset(n as isize)).listen_port = listen_port;
    let ref mut fresh6 = (*(*permp).offset(n as isize)).downstream;
    *fresh6 = downstream;
    return n as libc::c_int;
}
unsafe extern "C" fn mux_remove_remote_forwardings(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut pset: *mut permission_set = &mut (*sc).local_perms;
    let mut perm: *mut permission = 0 as *mut permission;
    let mut r: libc::c_int = 0;
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < (*pset).num_permitted_user {
        perm = &mut *((*pset).permitted_user).offset(i as isize) as *mut permission;
        if !((*perm).downstream != c) {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                    b"mux_remove_remote_forwardings\0",
                ))
                .as_ptr(),
                682 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"channel %d: cleanup remote forward for %s:%u\0" as *const u8
                    as *const libc::c_char,
                (*c).self_0,
                (*perm).listen_host,
                (*perm).listen_port,
            );
            r = sshpkt_start(ssh, 80 as libc::c_int as u_char);
            if r != 0 as libc::c_int
                || {
                    r = sshpkt_put_cstring(
                        ssh,
                        b"cancel-tcpip-forward\0" as *const u8 as *const libc::c_char
                            as *const libc::c_void,
                    );
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_u8(ssh, 0 as libc::c_int as u_char);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_cstring(
                        ssh,
                        channel_rfwd_bind_host((*perm).listen_host) as *const libc::c_void,
                    );
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_u32(ssh, (*perm).listen_port as u_int32_t);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_send(ssh);
                    r != 0 as libc::c_int
                }
            {
                sshfatal(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                        b"mux_remove_remote_forwardings\0",
                    ))
                    .as_ptr(),
                    691 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"channel %i\0" as *const u8 as *const libc::c_char,
                    (*c).self_0,
                );
            }
            fwd_perm_clear(perm);
        }
        i = i.wrapping_add(1);
        i;
    }
}
pub unsafe extern "C" fn channel_free(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: u_int = 0;
    let mut n: u_int = 0;
    let mut other: *mut Channel = 0 as *mut Channel;
    let mut cc: *mut channel_confirm = 0 as *mut channel_confirm;
    n = 0 as libc::c_int as u_int;
    i = 0 as libc::c_int as u_int;
    while i < (*sc).channels_alloc {
        other = *((*sc).channels).offset(i as isize);
        if !other.is_null() {
            n = n.wrapping_add(1);
            n;
            if (*c).type_0 == 16 as libc::c_int
                && (*other).type_0 == 20 as libc::c_int
                && (*other).mux_ctx == c as *mut libc::c_void
            {
                (*other).mux_ctx = 0 as *mut libc::c_void;
                (*other).type_0 = 4 as libc::c_int;
                (*other).istate = 3 as libc::c_int as u_int;
                (*other).ostate = 3 as libc::c_int as u_int;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"channel_free\0")).as_ptr(),
        722 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"channel %d: free: %s, nchannels %u\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        if !((*c).remote_name).is_null() {
            (*c).remote_name as *const libc::c_char
        } else {
            b"???\0" as *const u8 as *const libc::c_char
        },
        n,
    );
    if (*c).type_0 == 16 as libc::c_int {
        mux_remove_remote_forwardings(ssh, c);
        free((*c).mux_ctx);
        (*c).mux_ctx = 0 as *mut libc::c_void;
    } else if (*c).type_0 == 15 as libc::c_int {
        free((*c).mux_ctx);
        (*c).mux_ctx = 0 as *mut libc::c_void;
    }
    if log_level_get() as libc::c_int >= SYSLOG_LEVEL_DEBUG3 as libc::c_int {
        s = channel_open_message(ssh);
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"channel_free\0")).as_ptr(),
            735 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"channel %d: status: %s\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            s,
        );
        free(s as *mut libc::c_void);
    }
    channel_close_fds(ssh, c);
    sshbuf_free((*c).input);
    sshbuf_free((*c).output);
    sshbuf_free((*c).extended);
    (*c).extended = 0 as *mut sshbuf;
    (*c).output = (*c).extended;
    (*c).input = (*c).output;
    free((*c).remote_name as *mut libc::c_void);
    (*c).remote_name = 0 as *mut libc::c_char;
    free((*c).path as *mut libc::c_void);
    (*c).path = 0 as *mut libc::c_char;
    free((*c).listening_addr as *mut libc::c_void);
    (*c).listening_addr = 0 as *mut libc::c_char;
    free((*c).xctype as *mut libc::c_void);
    (*c).xctype = 0 as *mut libc::c_char;
    loop {
        cc = (*c).status_confirms.tqh_first;
        if cc.is_null() {
            break;
        }
        if ((*cc).abandon_cb).is_some() {
            ((*cc).abandon_cb).expect("non-null function pointer")(ssh, c, (*cc).ctx);
        }
        if !((*cc).entry.tqe_next).is_null() {
            (*(*cc).entry.tqe_next).entry.tqe_prev = (*cc).entry.tqe_prev;
        } else {
            (*c).status_confirms.tqh_last = (*cc).entry.tqe_prev;
        }
        *(*cc).entry.tqe_prev = (*cc).entry.tqe_next;
        freezero(
            cc as *mut libc::c_void,
            ::core::mem::size_of::<channel_confirm>() as libc::c_ulong,
        );
    }
    if ((*c).filter_cleanup).is_some() && !((*c).filter_ctx).is_null() {
        ((*c).filter_cleanup).expect("non-null function pointer")(
            ssh,
            (*c).self_0,
            (*c).filter_ctx,
        );
    }
    let ref mut fresh7 = *((*sc).channels).offset((*c).self_0 as isize);
    *fresh7 = 0 as *mut Channel;
    freezero(
        c as *mut libc::c_void,
        ::core::mem::size_of::<Channel>() as libc::c_ulong,
    );
}
pub unsafe extern "C" fn channel_free_all(mut ssh: *mut ssh) {
    let mut i: u_int = 0;
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    i = 0 as libc::c_int as u_int;
    while i < (*sc).channels_alloc {
        if !(*((*sc).channels).offset(i as isize)).is_null() {
            channel_free(ssh, *((*sc).channels).offset(i as isize));
        }
        i = i.wrapping_add(1);
        i;
    }
    free((*sc).channels as *mut libc::c_void);
    (*sc).channels = 0 as *mut *mut Channel;
    (*sc).channels_alloc = 0 as libc::c_int as u_int;
    free((*sc).x11_saved_display as *mut libc::c_void);
    (*sc).x11_saved_display = 0 as *mut libc::c_char;
    free((*sc).x11_saved_proto as *mut libc::c_void);
    (*sc).x11_saved_proto = 0 as *mut libc::c_char;
    free((*sc).x11_saved_data as *mut libc::c_void);
    (*sc).x11_saved_data = 0 as *mut libc::c_char;
    (*sc).x11_saved_data_len = 0 as libc::c_int as u_int;
    free((*sc).x11_fake_data as *mut libc::c_void);
    (*sc).x11_fake_data = 0 as *mut u_char;
    (*sc).x11_fake_data_len = 0 as libc::c_int as u_int;
}
pub unsafe extern "C" fn channel_close_all(mut ssh: *mut ssh) {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < (*(*ssh).chanctxt).channels_alloc {
        if !(*((*(*ssh).chanctxt).channels).offset(i as isize)).is_null() {
            channel_close_fds(ssh, *((*(*ssh).chanctxt).channels).offset(i as isize));
        }
        i = i.wrapping_add(1);
        i;
    }
}
pub unsafe extern "C" fn channel_stop_listening(mut ssh: *mut ssh) {
    let mut i: u_int = 0;
    let mut c: *mut Channel = 0 as *mut Channel;
    i = 0 as libc::c_int as u_int;
    while i < (*(*ssh).chanctxt).channels_alloc {
        c = *((*(*ssh).chanctxt).channels).offset(i as isize);
        if !c.is_null() {
            match (*c).type_0 {
                6 | 2 | 11 | 1 | 18 | 19 => {
                    channel_close_fd(ssh, c, &mut (*c).sock);
                    channel_free(ssh, c);
                }
                _ => {}
            }
        }
        i = i.wrapping_add(1);
        i;
    }
}
pub unsafe extern "C" fn channel_not_very_much_buffered_data(mut ssh: *mut ssh) -> libc::c_int {
    let mut i: u_int = 0;
    let mut maxsize: u_int = ssh_packet_get_maxsize(ssh);
    let mut c: *mut Channel = 0 as *mut Channel;
    i = 0 as libc::c_int as u_int;
    while i < (*(*ssh).chanctxt).channels_alloc {
        c = *((*(*ssh).chanctxt).channels).offset(i as isize);
        if !(c.is_null() || (*c).type_0 != 4 as libc::c_int) {
            if sshbuf_len((*c).output) > maxsize as libc::c_ulong {
                sshlog(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 36], &[libc::c_char; 36]>(
                        b"channel_not_very_much_buffered_data\0",
                    ))
                    .as_ptr(),
                    851 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"channel %d: big output buffer %zu > %u\0" as *const u8 as *const libc::c_char,
                    (*c).self_0,
                    sshbuf_len((*c).output),
                    maxsize,
                );
                return 0 as libc::c_int;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn channel_still_open(mut ssh: *mut ssh) -> libc::c_int {
    let mut i: u_int = 0;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut current_block_3: u64;
    i = 0 as libc::c_int as u_int;
    while i < (*(*ssh).chanctxt).channels_alloc {
        c = *((*(*ssh).chanctxt).channels).offset(i as isize);
        if !c.is_null() {
            match (*c).type_0 {
                1 | 2 | 11 | 15 | 5 | 6 | 13 | 21 | 12 | 14 | 17 | 18 | 19 | 10 => {}
                3 | 4 | 22 | 7 | 16 | 20 => {
                    current_block_3 = 707963862014799386;
                    match current_block_3 {
                        11554152168876335608 => {
                            sshfatal(
                                b"channels.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                    b"channel_still_open\0",
                                ))
                                .as_ptr(),
                                894 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                0 as *const libc::c_char,
                                b"bad channel type %d\0" as *const u8 as *const libc::c_char,
                                (*c).type_0,
                            );
                        }
                        _ => return 1 as libc::c_int,
                    }
                }
                _ => {
                    current_block_3 = 11554152168876335608;
                    match current_block_3 {
                        11554152168876335608 => {
                            sshfatal(
                                b"channels.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                    b"channel_still_open\0",
                                ))
                                .as_ptr(),
                                894 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                0 as *const libc::c_char,
                                b"bad channel type %d\0" as *const u8 as *const libc::c_char,
                                (*c).type_0,
                            );
                        }
                        _ => return 1 as libc::c_int,
                    }
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn channel_find_open(mut ssh: *mut ssh) -> libc::c_int {
    let mut i: u_int = 0;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut current_block_3: u64;
    i = 0 as libc::c_int as u_int;
    while i < (*(*ssh).chanctxt).channels_alloc {
        c = *((*(*ssh).chanctxt).channels).offset(i as isize);
        if !(c.is_null() || (*c).have_remote_id == 0) {
            match (*c).type_0 {
                5 | 13 | 21 | 22 | 1 | 2 | 11 | 15 | 16 | 20 | 3 | 12 | 14 | 17 | 18 | 19 => {}
                10 | 6 | 4 | 7 => {
                    current_block_3 = 3967879911585304446;
                    match current_block_3 {
                        1191833123431231384 => {
                            sshfatal(
                                b"channels.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                                    b"channel_find_open\0",
                                ))
                                .as_ptr(),
                                936 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                0 as *const libc::c_char,
                                b"bad channel type %d\0" as *const u8 as *const libc::c_char,
                                (*c).type_0,
                            );
                        }
                        _ => return i as libc::c_int,
                    }
                }
                _ => {
                    current_block_3 = 1191833123431231384;
                    match current_block_3 {
                        1191833123431231384 => {
                            sshfatal(
                                b"channels.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                                    b"channel_find_open\0",
                                ))
                                .as_ptr(),
                                936 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                0 as *const libc::c_char,
                                b"bad channel type %d\0" as *const u8 as *const libc::c_char,
                                (*c).type_0,
                            );
                        }
                        _ => return i as libc::c_int,
                    }
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return -(1 as libc::c_int);
}
pub unsafe extern "C" fn channel_format_extended_usage(
    mut c: *const Channel,
) -> *const libc::c_char {
    if (*c).efd == -(1 as libc::c_int) {
        return b"closed\0" as *const u8 as *const libc::c_char;
    }
    match (*c).extended_usage {
        2 => return b"write\0" as *const u8 as *const libc::c_char,
        1 => return b"read\0" as *const u8 as *const libc::c_char,
        0 => return b"ignore\0" as *const u8 as *const libc::c_char,
        _ => return b"UNKNOWN\0" as *const u8 as *const libc::c_char,
    };
}
unsafe extern "C" fn channel_format_status(mut c: *const Channel) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    xasprintf(
        &mut ret as *mut *mut libc::c_char,
        b"t%d [%s] %s%u i%u/%zu o%u/%zu e[%s]/%zu fd %d/%d/%d sock %d cc %d io 0x%02x/0x%02x\0"
            as *const u8 as *const libc::c_char,
        (*c).type_0,
        if !((*c).xctype).is_null() {
            (*c).xctype
        } else {
            (*c).ctype
        },
        if (*c).have_remote_id != 0 {
            b"r\0" as *const u8 as *const libc::c_char
        } else {
            b"nr\0" as *const u8 as *const libc::c_char
        },
        (*c).remote_id,
        (*c).istate,
        sshbuf_len((*c).input),
        (*c).ostate,
        sshbuf_len((*c).output),
        channel_format_extended_usage(c),
        sshbuf_len((*c).extended),
        (*c).rfd,
        (*c).wfd,
        (*c).efd,
        (*c).sock,
        (*c).ctl_chan,
        (*c).io_want,
        (*c).io_ready,
    );
    return ret;
}
pub unsafe extern "C" fn channel_open_message(mut ssh: *mut ssh) -> *mut libc::c_char {
    let mut buf: *mut sshbuf = 0 as *mut sshbuf;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut i: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    buf = sshbuf_new();
    if buf.is_null() {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"channel_open_message\0"))
                .as_ptr(),
            994 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_putf(
        buf,
        b"The following connections are open:\r\n\0" as *const u8 as *const libc::c_char,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"channel_open_message\0"))
                .as_ptr(),
            997 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
        );
    }
    let mut current_block_12: u64;
    i = 0 as libc::c_int as u_int;
    while i < (*(*ssh).chanctxt).channels_alloc {
        c = *((*(*ssh).chanctxt).channels).offset(i as isize);
        if !c.is_null() {
            match (*c).type_0 {
                1 | 2 | 11 | 5 | 6 | 14 | 17 | 15 | 18 | 19 => {}
                10 | 3 | 12 | 13 | 21 | 22 | 4 | 7 | 20 | 16 => {
                    current_block_12 = 14871782579726532874;
                    match current_block_12 {
                        9985215213307357364 => {
                            sshfatal(
                                b"channels.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                                    b"channel_open_message\0",
                                ))
                                .as_ptr(),
                                1033 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                0 as *const libc::c_char,
                                b"bad channel type %d\0" as *const u8 as *const libc::c_char,
                                (*c).type_0,
                            );
                        }
                        _ => {
                            cp = channel_format_status(c);
                            r = sshbuf_putf(
                                buf,
                                b"  #%d %.300s (%s)\r\n\0" as *const u8 as *const libc::c_char,
                                (*c).self_0,
                                (*c).remote_name,
                                cp,
                            );
                            if r != 0 as libc::c_int {
                                free(cp as *mut libc::c_void);
                                sshfatal(
                                    b"channels.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                                        b"channel_open_message\0",
                                    ))
                                    .as_ptr(),
                                    1028 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            free(cp as *mut libc::c_void);
                        }
                    }
                }
                _ => {
                    current_block_12 = 9985215213307357364;
                    match current_block_12 {
                        9985215213307357364 => {
                            sshfatal(
                                b"channels.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                                    b"channel_open_message\0",
                                ))
                                .as_ptr(),
                                1033 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                0 as *const libc::c_char,
                                b"bad channel type %d\0" as *const u8 as *const libc::c_char,
                                (*c).type_0,
                            );
                        }
                        _ => {
                            cp = channel_format_status(c);
                            r = sshbuf_putf(
                                buf,
                                b"  #%d %.300s (%s)\r\n\0" as *const u8 as *const libc::c_char,
                                (*c).self_0,
                                (*c).remote_name,
                                cp,
                            );
                            if r != 0 as libc::c_int {
                                free(cp as *mut libc::c_void);
                                sshfatal(
                                    b"channels.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                                        b"channel_open_message\0",
                                    ))
                                    .as_ptr(),
                                    1028 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            free(cp as *mut libc::c_void);
                        }
                    }
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    ret = sshbuf_dup_string(buf);
    if ret.is_null() {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"channel_open_message\0"))
                .as_ptr(),
            1038 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_dup_string\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(buf);
    return ret;
}
unsafe extern "C" fn open_preamble(
    mut ssh: *mut ssh,
    mut where_0: *const libc::c_char,
    mut c: *mut Channel,
    mut type_0: *const libc::c_char,
) {
    let mut r: libc::c_int = 0;
    r = sshpkt_start(ssh, 90 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_cstring(ssh, type_0 as *const libc::c_void);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, (*c).self_0 as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, (*c).local_window);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, (*c).local_maxpacket);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"open_preamble\0"))
                .as_ptr(),
            1053 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"%s: channel %i: open\0" as *const u8 as *const libc::c_char,
            where_0,
            (*c).self_0,
        );
    }
}
pub unsafe extern "C" fn channel_send_open(mut ssh: *mut ssh, mut id: libc::c_int) {
    let mut c: *mut Channel = channel_lookup(ssh, id);
    let mut r: libc::c_int = 0;
    if c.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"channel_send_open\0"))
                .as_ptr(),
            1064 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"channel_send_open: %d: bad id\0" as *const u8 as *const libc::c_char,
            id,
        );
        return;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"channel_send_open\0"))
            .as_ptr(),
        1067 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: send open\0" as *const u8 as *const libc::c_char,
        id,
    );
    open_preamble(
        ssh,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"channel_send_open\0"))
            .as_ptr(),
        c,
        (*c).ctype,
    );
    r = sshpkt_send(ssh);
    if r != 0 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"channel_send_open\0"))
                .as_ptr(),
            1070 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
}
pub unsafe extern "C" fn channel_request_start(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut service: *mut libc::c_char,
    mut wantconfirm: libc::c_int,
) {
    let mut c: *mut Channel = channel_lookup(ssh, id);
    let mut r: libc::c_int = 0;
    if c.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_request_start\0"))
                .as_ptr(),
            1080 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%d: unknown channel id\0" as *const u8 as *const libc::c_char,
            id,
        );
        return;
    }
    if (*c).have_remote_id == 0 {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_request_start\0"))
                .as_ptr(),
            1084 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d: no remote id\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_request_start\0"))
            .as_ptr(),
        1086 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: request %s confirm %d\0" as *const u8 as *const libc::c_char,
        id,
        service,
        wantconfirm,
    );
    r = sshpkt_start(ssh, 98 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_u32(ssh, (*c).remote_id);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_cstring(ssh, service as *const libc::c_void);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u8(ssh, wantconfirm as u_char);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_request_start\0"))
                .as_ptr(),
            1091 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
}
pub unsafe extern "C" fn channel_register_status_confirm(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut cb: Option<channel_confirm_cb>,
    mut abandon_cb: Option<channel_confirm_abandon_cb>,
    mut ctx: *mut libc::c_void,
) {
    let mut cc: *mut channel_confirm = 0 as *mut channel_confirm;
    let mut c: *mut Channel = 0 as *mut Channel;
    c = channel_lookup(ssh, id);
    if c.is_null() {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 32], &[libc::c_char; 32]>(
                b"channel_register_status_confirm\0",
            ))
            .as_ptr(),
            1103 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%d: bad id\0" as *const u8 as *const libc::c_char,
            id,
        );
    }
    cc = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<channel_confirm>() as libc::c_ulong,
    ) as *mut channel_confirm;
    (*cc).cb = cb;
    (*cc).abandon_cb = abandon_cb;
    (*cc).ctx = ctx;
    (*cc).entry.tqe_next = 0 as *mut channel_confirm;
    (*cc).entry.tqe_prev = (*c).status_confirms.tqh_last;
    *(*c).status_confirms.tqh_last = cc;
    (*c).status_confirms.tqh_last = &mut (*cc).entry.tqe_next;
}
pub unsafe extern "C" fn channel_register_open_confirm(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut fn_0: Option<channel_open_fn>,
    mut ctx: *mut libc::c_void,
) {
    let mut c: *mut Channel = channel_lookup(ssh, id);
    if c.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"channel_register_open_confirm\0",
            ))
            .as_ptr(),
            1119 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%d: bad id\0" as *const u8 as *const libc::c_char,
            id,
        );
        return;
    }
    (*c).open_confirm = fn_0;
    (*c).open_confirm_ctx = ctx;
}
pub unsafe extern "C" fn channel_register_cleanup(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut fn_0: Option<channel_callback_fn>,
    mut do_close: libc::c_int,
) {
    let mut c: *mut Channel = channel_by_id(ssh, id);
    if c.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"channel_register_cleanup\0",
            ))
            .as_ptr(),
            1133 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%d: bad id\0" as *const u8 as *const libc::c_char,
            id,
        );
        return;
    }
    (*c).detach_user = fn_0;
    (*c).detach_close = do_close;
}
pub unsafe extern "C" fn channel_cancel_cleanup(mut ssh: *mut ssh, mut id: libc::c_int) {
    let mut c: *mut Channel = channel_by_id(ssh, id);
    if c.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"channel_cancel_cleanup\0",
            ))
            .as_ptr(),
            1146 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%d: bad id\0" as *const u8 as *const libc::c_char,
            id,
        );
        return;
    }
    (*c).detach_user = None;
    (*c).detach_close = 0 as libc::c_int;
}
pub unsafe extern "C" fn channel_register_filter(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut ifn: Option<channel_infilter_fn>,
    mut ofn: Option<channel_outfilter_fn>,
    mut cfn: Option<channel_filter_cleanup_fn>,
    mut ctx: *mut libc::c_void,
) {
    let mut c: *mut Channel = channel_lookup(ssh, id);
    if c.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"channel_register_filter\0",
            ))
            .as_ptr(),
            1160 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%d: bad id\0" as *const u8 as *const libc::c_char,
            id,
        );
        return;
    }
    (*c).input_filter = ifn;
    (*c).output_filter = ofn;
    (*c).filter_ctx = ctx;
    (*c).filter_cleanup = cfn;
}
pub unsafe extern "C" fn channel_set_fds(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut rfd: libc::c_int,
    mut wfd: libc::c_int,
    mut efd: libc::c_int,
    mut extusage: libc::c_int,
    mut nonblock: libc::c_int,
    mut is_tty: libc::c_int,
    mut window_max: u_int,
) {
    let mut c: *mut Channel = channel_lookup(ssh, id);
    let mut r: libc::c_int = 0;
    if c.is_null() || (*c).type_0 != 10 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"channel_set_fds\0"))
                .as_ptr(),
            1177 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel_activate for non-larval channel %d.\0" as *const u8 as *const libc::c_char,
            id,
        );
    }
    if (*c).have_remote_id == 0 {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"channel_set_fds\0"))
                .as_ptr(),
            1179 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d: no remote id\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    channel_register_fds(ssh, c, rfd, wfd, efd, extusage, nonblock, is_tty);
    (*c).type_0 = 4 as libc::c_int;
    (*c).lastused = monotime();
    (*c).local_window_max = window_max;
    (*c).local_window = (*c).local_window_max;
    r = sshpkt_start(ssh, 93 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_u32(ssh, (*c).remote_id);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, (*c).local_window);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"channel_set_fds\0"))
                .as_ptr(),
            1190 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
}
unsafe extern "C" fn channel_pre_listener(mut _ssh: *mut ssh, mut c: *mut Channel) {
    (*c).io_want = 0x10 as libc::c_int as u_int;
}
unsafe extern "C" fn channel_pre_connecting(mut _ssh: *mut ssh, mut c: *mut Channel) {
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"channel_pre_connecting\0"))
            .as_ptr(),
        1202 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"channel %d: waiting for connection\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    (*c).io_want = 0x20 as libc::c_int as u_int;
}
unsafe extern "C" fn channel_pre_open(mut ssh: *mut ssh, mut c: *mut Channel) {
    (*c).io_want = 0 as libc::c_int as u_int;
    if (*c).istate == 0 as libc::c_int as libc::c_uint
        && (*c).remote_window > 0 as libc::c_int as libc::c_uint
        && sshbuf_len((*c).input) < (*c).remote_window as libc::c_ulong
        && sshbuf_check_reserve(
            (*c).input,
            (16 as libc::c_int * 1024 as libc::c_int) as size_t,
        ) == 0 as libc::c_int
    {
        (*c).io_want |= 0x1 as libc::c_int as libc::c_uint;
    }
    if (*c).ostate == 0 as libc::c_int as libc::c_uint
        || (*c).ostate == 1 as libc::c_int as libc::c_uint
    {
        if sshbuf_len((*c).output) > 0 as libc::c_int as libc::c_ulong {
            (*c).io_want |= 0x2 as libc::c_int as libc::c_uint;
        } else if (*c).ostate == 1 as libc::c_int as libc::c_uint {
            if (*c).extended_usage == 2 as libc::c_int
                && (*c).efd != -(1 as libc::c_int)
                && ((*c).flags & (0x8 as libc::c_int | 0x2 as libc::c_int) == 0
                    || sshbuf_len((*c).extended) > 0 as libc::c_int as libc::c_ulong)
            {
                sshlog(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                        b"channel_pre_open\0",
                    ))
                    .as_ptr(),
                    1223 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"channel %d: obuf_empty delayed efd %d/(%zu)\0" as *const u8
                        as *const libc::c_char,
                    (*c).self_0,
                    (*c).efd,
                    sshbuf_len((*c).extended),
                );
            } else {
                chan_obuf_empty(ssh, c);
            }
        }
    }
    if (*c).efd != -(1 as libc::c_int)
        && !((*c).istate == 3 as libc::c_int as libc::c_uint
            && (*c).ostate == 3 as libc::c_int as libc::c_uint)
    {
        if (*c).extended_usage == 2 as libc::c_int
            && sshbuf_len((*c).extended) > 0 as libc::c_int as libc::c_ulong
        {
            (*c).io_want |= 0x8 as libc::c_int as libc::c_uint;
        } else if (*c).efd != -(1 as libc::c_int)
            && (*c).flags & 0x4 as libc::c_int == 0
            && ((*c).extended_usage == 1 as libc::c_int || (*c).extended_usage == 0 as libc::c_int)
            && sshbuf_len((*c).extended) < (*c).remote_window as libc::c_ulong
        {
            (*c).io_want |= 0x4 as libc::c_int as libc::c_uint;
        }
    }
}
unsafe extern "C" fn x11_open_helper(mut ssh: *mut ssh, mut b: *mut sshbuf) -> libc::c_int {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut ucp: *mut u_char = 0 as *mut u_char;
    let mut proto_len: u_int = 0;
    let mut data_len: u_int = 0;
    if (*sc).x11_refuse_time != 0 as libc::c_int as libc::c_long
        && monotime() >= (*sc).x11_refuse_time
    {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"x11_open_helper\0"))
                .as_ptr(),
            1263 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"Rejected X11 connection after ForwardX11Timeout expired\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if sshbuf_len(b) < 12 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    ucp = sshbuf_mutable_ptr(b);
    if *ucp.offset(0 as libc::c_int as isize) as libc::c_int == 0x42 as libc::c_int {
        proto_len = (256 as libc::c_int * *ucp.offset(6 as libc::c_int as isize) as libc::c_int
            + *ucp.offset(7 as libc::c_int as isize) as libc::c_int) as u_int;
        data_len = (256 as libc::c_int * *ucp.offset(8 as libc::c_int as isize) as libc::c_int
            + *ucp.offset(9 as libc::c_int as isize) as libc::c_int) as u_int;
    } else if *ucp.offset(0 as libc::c_int as isize) as libc::c_int == 0x6c as libc::c_int {
        proto_len = (*ucp.offset(6 as libc::c_int as isize) as libc::c_int
            + 256 as libc::c_int * *ucp.offset(7 as libc::c_int as isize) as libc::c_int)
            as u_int;
        data_len = (*ucp.offset(8 as libc::c_int as isize) as libc::c_int
            + 256 as libc::c_int * *ucp.offset(9 as libc::c_int as isize) as libc::c_int)
            as u_int;
    } else {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"x11_open_helper\0"))
                .as_ptr(),
            1281 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"Initial X11 packet contains bad byte order byte: 0x%x\0" as *const u8
                as *const libc::c_char,
            *ucp.offset(0 as libc::c_int as isize) as libc::c_int,
        );
        return -(1 as libc::c_int);
    }
    if sshbuf_len(b)
        < (12 as libc::c_int as libc::c_uint)
            .wrapping_add(
                proto_len.wrapping_add(3 as libc::c_int as libc::c_uint)
                    & !(3 as libc::c_int) as libc::c_uint,
            )
            .wrapping_add(
                data_len.wrapping_add(3 as libc::c_int as libc::c_uint)
                    & !(3 as libc::c_int) as libc::c_uint,
            ) as libc::c_ulong
    {
        return 0 as libc::c_int;
    }
    if proto_len as libc::c_ulong != strlen((*sc).x11_saved_proto)
        || memcmp(
            ucp.offset(12 as libc::c_int as isize) as *const libc::c_void,
            (*sc).x11_saved_proto as *const libc::c_void,
            proto_len as libc::c_ulong,
        ) != 0 as libc::c_int
    {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"x11_open_helper\0"))
                .as_ptr(),
            1293 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"X11 connection uses different authentication protocol.\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if data_len != (*sc).x11_fake_data_len
        || timingsafe_bcmp(
            ucp.offset(12 as libc::c_int as isize).offset(
                (proto_len.wrapping_add(3 as libc::c_int as libc::c_uint)
                    & !(3 as libc::c_int) as libc::c_uint) as isize,
            ) as *const libc::c_void,
            (*sc).x11_fake_data as *const libc::c_void,
            (*sc).x11_fake_data_len as size_t,
        ) != 0 as libc::c_int
    {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"x11_open_helper\0"))
                .as_ptr(),
            1300 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"X11 auth data does not match fake data.\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if (*sc).x11_fake_data_len != (*sc).x11_saved_data_len {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"x11_open_helper\0"))
                .as_ptr(),
            1306 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"X11 fake_data_len %d != saved_data_len %d\0" as *const u8 as *const libc::c_char,
            (*sc).x11_fake_data_len,
            (*sc).x11_saved_data_len,
        );
        return -(1 as libc::c_int);
    }
    memcpy(
        ucp.offset(12 as libc::c_int as isize).offset(
            (proto_len.wrapping_add(3 as libc::c_int as libc::c_uint)
                & !(3 as libc::c_int) as libc::c_uint) as isize,
        ) as *mut libc::c_void,
        (*sc).x11_saved_data as *const libc::c_void,
        (*sc).x11_saved_data_len as libc::c_ulong,
    );
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn channel_force_close(
    mut ssh: *mut ssh,
    mut c: *mut Channel,
    mut abandon: libc::c_int,
) {
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"channel_force_close\0"))
            .as_ptr(),
        1322 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"channel %d: forcibly closing\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    if (*c).istate == 0 as libc::c_int as libc::c_uint {
        chan_read_failed(ssh, c);
    }
    if (*c).istate == 1 as libc::c_int as libc::c_uint {
        sshbuf_reset((*c).input);
        chan_ibuf_empty(ssh, c);
    }
    if (*c).ostate == 0 as libc::c_int as libc::c_uint
        || (*c).ostate == 1 as libc::c_int as libc::c_uint
    {
        sshbuf_reset((*c).output);
        chan_write_failed(ssh, c);
    }
    if ((*c).detach_user).is_some() {
        ((*c).detach_user).expect("non-null function pointer")(
            ssh,
            (*c).self_0,
            1 as libc::c_int,
            0 as *mut libc::c_void,
        );
    }
    if (*c).efd != -(1 as libc::c_int) {
        channel_close_fd(ssh, c, &mut (*c).efd);
    }
    if abandon != 0 {
        (*c).type_0 = 17 as libc::c_int;
    }
    (*c).inactive_deadline = 0 as libc::c_int as u_int;
    (*c).lastused = 0 as libc::c_int as time_t;
}
unsafe extern "C" fn channel_pre_x11_open(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut ret: libc::c_int = x11_open_helper(ssh, (*c).output);
    if ret == 1 as libc::c_int {
        (*c).type_0 = 4 as libc::c_int;
        (*c).lastused = monotime();
        channel_pre_open(ssh, c);
    } else if ret == -(1 as libc::c_int) {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"channel_pre_x11_open\0"))
                .as_ptr(),
            1358 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"X11 connection rejected because of wrong authentication.\0" as *const u8
                as *const libc::c_char,
        );
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"channel_pre_x11_open\0"))
                .as_ptr(),
            1360 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"X11 rejected %d i%d/o%d\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            (*c).istate,
            (*c).ostate,
        );
        channel_force_close(ssh, c, 0 as libc::c_int);
    }
}
unsafe extern "C" fn channel_pre_mux_client(mut ssh: *mut ssh, mut c: *mut Channel) {
    (*c).io_want = 0 as libc::c_int as u_int;
    if (*c).istate == 0 as libc::c_int as libc::c_uint
        && (*c).mux_pause == 0
        && sshbuf_check_reserve(
            (*c).input,
            (16 as libc::c_int * 1024 as libc::c_int) as size_t,
        ) == 0 as libc::c_int
    {
        (*c).io_want |= 0x1 as libc::c_int as libc::c_uint;
    }
    if (*c).istate == 1 as libc::c_int as libc::c_uint {
        sshbuf_reset((*c).input);
        chan_ibuf_empty(ssh, c);
        chan_rcvd_oclose(ssh, c);
    }
    if (*c).ostate == 0 as libc::c_int as libc::c_uint
        || (*c).ostate == 1 as libc::c_int as libc::c_uint
    {
        if sshbuf_len((*c).output) > 0 as libc::c_int as libc::c_ulong {
            (*c).io_want |= 0x2 as libc::c_int as libc::c_uint;
        } else if (*c).ostate == 1 as libc::c_int as libc::c_uint {
            chan_obuf_empty(ssh, c);
        }
    }
}
unsafe extern "C" fn channel_decode_socks4(
    mut c: *mut Channel,
    mut input: *mut sshbuf,
    mut output: *mut sshbuf,
) -> libc::c_int {
    let mut p: *const u_char = 0 as *const u_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut len: u_int = 0;
    let mut have: u_int = 0;
    let mut i: u_int = 0;
    let mut found: u_int = 0;
    let mut need: u_int = 0;
    let mut username: [libc::c_char; 256] = [0; 256];
    let mut s4_req: C2RustUnnamed_5 = C2RustUnnamed_5 {
        version: 0,
        command: 0,
        dest_port: 0,
        dest_addr: in_addr { s_addr: 0 },
    };
    let mut s4_rsp: C2RustUnnamed_5 = C2RustUnnamed_5 {
        version: 0,
        command: 0,
        dest_port: 0,
        dest_addr: in_addr { s_addr: 0 },
    };
    let mut r: libc::c_int = 0;
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks4\0"))
            .as_ptr(),
        1404 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: decode socks4\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    have = sshbuf_len(input) as u_int;
    len = ::core::mem::size_of::<C2RustUnnamed_5>() as libc::c_ulong as u_int;
    if have < len {
        return 0 as libc::c_int;
    }
    p = sshbuf_ptr(input);
    need = 1 as libc::c_int as u_int;
    if *p.offset(4 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
        && *p.offset(5 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
        && *p.offset(6 as libc::c_int as isize) as libc::c_int == 0 as libc::c_int
        && *p.offset(7 as libc::c_int as isize) as libc::c_int != 0 as libc::c_int
    {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks4\0"))
                .as_ptr(),
            1415 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: socks4a request\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        need = 2 as libc::c_int as u_int;
    }
    found = 0 as libc::c_int as u_int;
    i = len;
    while i < have {
        if *p.offset(i as isize) as libc::c_int == '\0' as i32 {
            found = found.wrapping_add(1);
            found;
            if found == need {
                break;
            }
        }
        if i > 1024 as libc::c_int as libc::c_uint {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"channel_decode_socks4\0",
                ))
                .as_ptr(),
                1429 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"channel %d: decode socks4: too long\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
            return -(1 as libc::c_int);
        }
        i = i.wrapping_add(1);
        i;
    }
    if found < need {
        return 0 as libc::c_int;
    }
    r = sshbuf_get(
        input,
        &mut s4_req.version as *mut u_int8_t as *mut libc::c_void,
        1 as libc::c_int as size_t,
    );
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get(
                input,
                &mut s4_req.command as *mut u_int8_t as *mut libc::c_void,
                1 as libc::c_int as size_t,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get(
                input,
                &mut s4_req.dest_port as *mut u_int16_t as *mut libc::c_void,
                2 as libc::c_int as size_t,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get(
                input,
                &mut s4_req.dest_addr as *mut in_addr as *mut libc::c_void,
                4 as libc::c_int as size_t,
            );
            r != 0 as libc::c_int
        }
    {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks4\0"))
                .as_ptr(),
            1439 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            ssh_err(r),
            b"channels %d: decode socks4\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        return -(1 as libc::c_int);
    }
    have = sshbuf_len(input) as u_int;
    p = sshbuf_ptr(input);
    if (memchr(p as *const libc::c_void, '\0' as i32, have as libc::c_ulong)).is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks4\0"))
                .as_ptr(),
            1445 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"channel %d: decode socks4: unterminated user\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        return -(1 as libc::c_int);
    }
    len = strlen(p as *const libc::c_char) as u_int;
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks4\0"))
            .as_ptr(),
        1449 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: decode socks4: user %s/%d\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        p,
        len,
    );
    len = len.wrapping_add(1);
    len;
    strlcpy(
        username.as_mut_ptr(),
        p as *const libc::c_char,
        ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong,
    );
    r = sshbuf_consume(input, len as size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks4\0"))
                .as_ptr(),
            1453 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %d: consume\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    free((*c).path as *mut libc::c_void);
    (*c).path = 0 as *mut libc::c_char;
    if need == 1 as libc::c_int as libc::c_uint {
        host = inet_ntoa(s4_req.dest_addr);
        (*c).path = xstrdup(host);
    } else {
        have = sshbuf_len(input) as u_int;
        p = sshbuf_ptr(input);
        if (memchr(p as *const libc::c_void, '\0' as i32, have as libc::c_ulong)).is_null() {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"channel_decode_socks4\0",
                ))
                .as_ptr(),
                1464 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"channel %d: decode socks4a: host not nul terminated\0" as *const u8
                    as *const libc::c_char,
                (*c).self_0,
            );
            return -(1 as libc::c_int);
        }
        len = strlen(p as *const libc::c_char) as u_int;
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks4\0"))
                .as_ptr(),
            1469 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: decode socks4a: host %s/%d\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            p,
            len,
        );
        len = len.wrapping_add(1);
        len;
        if len > 1025 as libc::c_int as libc::c_uint {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"channel_decode_socks4\0",
                ))
                .as_ptr(),
                1473 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"channel %d: hostname \"%.100s\" too long\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
                p,
            );
            return -(1 as libc::c_int);
        }
        (*c).path = xstrdup(p as *const libc::c_char);
        r = sshbuf_consume(input, len as size_t);
        if r != 0 as libc::c_int {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"channel_decode_socks4\0",
                ))
                .as_ptr(),
                1478 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %d: consume\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
    }
    (*c).host_port = __bswap_16(s4_req.dest_port) as libc::c_int;
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks4\0"))
            .as_ptr(),
        1483 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: dynamic request: socks4 host %s port %u command %u\0" as *const u8
            as *const libc::c_char,
        (*c).self_0,
        (*c).path,
        (*c).host_port,
        s4_req.command as libc::c_int,
    );
    if s4_req.command as libc::c_int != 1 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks4\0"))
                .as_ptr(),
            1487 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"channel %d: cannot handle: %s cn %d\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            if need == 1 as libc::c_int as libc::c_uint {
                b"SOCKS4\0" as *const u8 as *const libc::c_char
            } else {
                b"SOCKS4A\0" as *const u8 as *const libc::c_char
            },
            s4_req.command as libc::c_int,
        );
        return -(1 as libc::c_int);
    }
    s4_rsp.version = 0 as libc::c_int as u_int8_t;
    s4_rsp.command = 90 as libc::c_int as u_int8_t;
    s4_rsp.dest_port = 0 as libc::c_int as u_int16_t;
    s4_rsp.dest_addr.s_addr = 0 as libc::c_int as in_addr_t;
    r = sshbuf_put(
        output,
        &mut s4_rsp as *mut C2RustUnnamed_5 as *const libc::c_void,
        ::core::mem::size_of::<C2RustUnnamed_5>() as libc::c_ulong,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks4\0"))
                .as_ptr(),
            1495 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %d: append reply\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn channel_decode_socks5(
    mut c: *mut Channel,
    mut input: *mut sshbuf,
    mut output: *mut sshbuf,
) -> libc::c_int {
    let mut s5_req: C2RustUnnamed_4 = C2RustUnnamed_4 {
        version: 0,
        command: 0,
        reserved: 0,
        atyp: 0,
    };
    let mut s5_rsp: C2RustUnnamed_4 = C2RustUnnamed_4 {
        version: 0,
        command: 0,
        reserved: 0,
        atyp: 0,
    };
    let mut dest_port: u_int16_t = 0;
    let mut dest_addr: [libc::c_char; 256] = [0; 256];
    let mut ntop: [libc::c_char; 46] = [0; 46];
    let mut p: *const u_char = 0 as *const u_char;
    let mut have: u_int = 0;
    let mut need: u_int = 0;
    let mut i: u_int = 0;
    let mut found: u_int = 0;
    let mut nmethods: u_int = 0;
    let mut addrlen: u_int = 0;
    let mut af: u_int = 0;
    let mut r: libc::c_int = 0;
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks5\0"))
            .as_ptr(),
        1524 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: decode socks5\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    p = sshbuf_ptr(input);
    if *p.offset(0 as libc::c_int as isize) as libc::c_int != 0x5 as libc::c_int {
        return -(1 as libc::c_int);
    }
    have = sshbuf_len(input) as u_int;
    if (*c).flags & 0x1000 as libc::c_int == 0 {
        if have < 2 as libc::c_int as libc::c_uint {
            return 0 as libc::c_int;
        }
        nmethods = *p.offset(1 as libc::c_int as isize) as u_int;
        if have < nmethods.wrapping_add(2 as libc::c_int as libc::c_uint) {
            return 0 as libc::c_int;
        }
        found = 0 as libc::c_int as u_int;
        i = 2 as libc::c_int as u_int;
        while i < nmethods.wrapping_add(2 as libc::c_int as libc::c_uint) {
            if *p.offset(i as isize) as libc::c_int == 0 as libc::c_int {
                found = 1 as libc::c_int as u_int;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
        if found == 0 {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"channel_decode_socks5\0",
                ))
                .as_ptr(),
                1545 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"channel %d: method SSH_SOCKS5_NOAUTH not found\0" as *const u8
                    as *const libc::c_char,
                (*c).self_0,
            );
            return -(1 as libc::c_int);
        }
        r = sshbuf_consume(
            input,
            nmethods.wrapping_add(2 as libc::c_int as libc::c_uint) as size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"channel_decode_socks5\0",
                ))
                .as_ptr(),
                1549 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %d: consume\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
        r = sshbuf_put_u8(output, 0x5 as libc::c_int as u_char);
        if r != 0 as libc::c_int || {
            r = sshbuf_put_u8(output, 0 as libc::c_int as u_char);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"channel_decode_socks5\0",
                ))
                .as_ptr(),
                1553 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %d: append reply\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
        (*c).flags |= 0x1000 as libc::c_int;
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks5\0"))
                .as_ptr(),
            1555 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: socks5 auth done\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        return 0 as libc::c_int;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks5\0"))
            .as_ptr(),
        1558 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: socks5 post auth\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    if (have as libc::c_ulong)
        < (::core::mem::size_of::<C2RustUnnamed_4>() as libc::c_ulong)
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
    {
        return 0 as libc::c_int;
    }
    memcpy(
        &mut s5_req as *mut C2RustUnnamed_4 as *mut libc::c_void,
        p as *const libc::c_void,
        ::core::mem::size_of::<C2RustUnnamed_4>() as libc::c_ulong,
    );
    if s5_req.version as libc::c_int != 0x5 as libc::c_int
        || s5_req.command as libc::c_int != 0x1 as libc::c_int
        || s5_req.reserved as libc::c_int != 0 as libc::c_int
    {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks5\0"))
                .as_ptr(),
            1565 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: only socks5 connect supported\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        return -(1 as libc::c_int);
    }
    match s5_req.atyp as libc::c_int {
        1 => {
            addrlen = 4 as libc::c_int as u_int;
            af = 2 as libc::c_int as u_int;
        }
        3 => {
            addrlen = *p.offset(::core::mem::size_of::<C2RustUnnamed_4>() as libc::c_ulong as isize)
                as u_int;
            af = -(1 as libc::c_int) as u_int;
        }
        4 => {
            addrlen = 16 as libc::c_int as u_int;
            af = 10 as libc::c_int as u_int;
        }
        _ => {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"channel_decode_socks5\0",
                ))
                .as_ptr(),
                1582 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"channel %d: bad socks5 atyp %d\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
                s5_req.atyp as libc::c_int,
            );
            return -(1 as libc::c_int);
        }
    }
    need = (::core::mem::size_of::<C2RustUnnamed_4>() as libc::c_ulong)
        .wrapping_add(addrlen as libc::c_ulong)
        .wrapping_add(2 as libc::c_int as libc::c_ulong) as u_int;
    if s5_req.atyp as libc::c_int == 0x3 as libc::c_int {
        need = need.wrapping_add(1);
        need;
    }
    if have < need {
        return 0 as libc::c_int;
    }
    r = sshbuf_consume(
        input,
        ::core::mem::size_of::<C2RustUnnamed_4>() as libc::c_ulong,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks5\0"))
                .as_ptr(),
            1591 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %d: consume\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    if s5_req.atyp as libc::c_int == 0x3 as libc::c_int {
        r = sshbuf_consume(input, 1 as libc::c_int as size_t);
        if r != 0 as libc::c_int {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"channel_decode_socks5\0",
                ))
                .as_ptr(),
                1595 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %d: consume\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
    }
    r = sshbuf_get(
        input,
        &mut dest_addr as *mut [libc::c_char; 256] as *mut libc::c_void,
        addrlen as size_t,
    );
    if r != 0 as libc::c_int || {
        r = sshbuf_get(
            input,
            &mut dest_port as *mut u_int16_t as *mut libc::c_void,
            2 as libc::c_int as size_t,
        );
        r != 0 as libc::c_int
    } {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks5\0"))
                .as_ptr(),
            1599 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            ssh_err(r),
            b"channel %d: parse addr/port\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        return -(1 as libc::c_int);
    }
    dest_addr[addrlen as usize] = '\0' as i32 as libc::c_char;
    free((*c).path as *mut libc::c_void);
    (*c).path = 0 as *mut libc::c_char;
    if s5_req.atyp as libc::c_int == 0x3 as libc::c_int {
        if addrlen >= 1025 as libc::c_int as libc::c_uint {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"channel_decode_socks5\0",
                ))
                .as_ptr(),
                1608 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"channel %d: dynamic request: socks5 hostname \"%.100s\" too long\0" as *const u8
                    as *const libc::c_char,
                (*c).self_0,
                dest_addr.as_mut_ptr(),
            );
            return -(1 as libc::c_int);
        }
        (*c).path = xstrdup(dest_addr.as_mut_ptr());
    } else {
        if (inet_ntop(
            af as libc::c_int,
            dest_addr.as_mut_ptr() as *const libc::c_void,
            ntop.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 46]>() as libc::c_ulong as socklen_t,
        ))
        .is_null()
        {
            return -(1 as libc::c_int);
        }
        (*c).path = xstrdup(ntop.as_mut_ptr());
    }
    (*c).host_port = __bswap_16(dest_port) as libc::c_int;
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks5\0"))
            .as_ptr(),
        1620 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: dynamic request: socks5 host %s port %u command %u\0" as *const u8
            as *const libc::c_char,
        (*c).self_0,
        (*c).path,
        (*c).host_port,
        s5_req.command as libc::c_int,
    );
    s5_rsp.version = 0x5 as libc::c_int as u_int8_t;
    s5_rsp.command = 0 as libc::c_int as u_int8_t;
    s5_rsp.reserved = 0 as libc::c_int as u_int8_t;
    s5_rsp.atyp = 0x1 as libc::c_int as u_int8_t;
    dest_port = 0 as libc::c_int as u_int16_t;
    r = sshbuf_put(
        output,
        &mut s5_rsp as *mut C2RustUnnamed_4 as *const libc::c_void,
        ::core::mem::size_of::<C2RustUnnamed_4>() as libc::c_ulong,
    );
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(output, __bswap_32(0 as libc::c_int as in_addr_t));
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put(
                output,
                &mut dest_port as *mut u_int16_t as *const libc::c_void,
                ::core::mem::size_of::<u_int16_t>() as libc::c_ulong,
            );
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"channel_decode_socks5\0"))
                .as_ptr(),
            1631 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %d: append reply\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn channel_connect_stdio_fwd(
    mut ssh: *mut ssh,
    mut host_to_connect: *const libc::c_char,
    mut port_to_connect: u_short,
    mut in_0: libc::c_int,
    mut out: libc::c_int,
    mut nonblock: libc::c_int,
) -> *mut Channel {
    let mut c: *mut Channel = 0 as *mut Channel;
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"channel_connect_stdio_fwd\0"))
            .as_ptr(),
        1642 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"%s:%d\0" as *const u8 as *const libc::c_char,
        host_to_connect,
        port_to_connect as libc::c_int,
    );
    c = channel_new(
        ssh,
        b"stdio-forward\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        3 as libc::c_int,
        in_0,
        out,
        -(1 as libc::c_int),
        (64 as libc::c_int * (32 as libc::c_int * 1024 as libc::c_int)) as u_int,
        (32 as libc::c_int * 1024 as libc::c_int) as u_int,
        0 as libc::c_int,
        b"stdio-forward\0" as *const u8 as *const libc::c_char,
        nonblock,
    );
    (*c).path = xstrdup(host_to_connect);
    (*c).host_port = port_to_connect as libc::c_int;
    (*c).listening_port = 0 as libc::c_int;
    (*c).force_drain = 1 as libc::c_int;
    channel_register_fds(
        ssh,
        c,
        in_0,
        out,
        -(1 as libc::c_int),
        0 as libc::c_int,
        1 as libc::c_int,
        0 as libc::c_int,
    );
    port_open_helper(
        ssh,
        c,
        b"direct-tcpip\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    return c;
}
unsafe extern "C" fn channel_pre_dynamic(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut p: *const u_char = 0 as *const u_char;
    let mut have: u_int = 0;
    let mut ret: libc::c_int = 0;
    (*c).io_want = 0 as libc::c_int as u_int;
    have = sshbuf_len((*c).input) as u_int;
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"channel_pre_dynamic\0"))
            .as_ptr(),
        1669 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: pre_dynamic: have %d\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        have,
    );
    if have < 3 as libc::c_int as libc::c_uint {
        (*c).io_want |= 0x1 as libc::c_int as libc::c_uint;
        return;
    }
    p = sshbuf_ptr((*c).input);
    match *p.offset(0 as libc::c_int as isize) as libc::c_int {
        4 => {
            ret = channel_decode_socks4(c, (*c).input, (*c).output);
        }
        5 => {
            ret = channel_decode_socks5(c, (*c).input, (*c).output);
        }
        _ => {
            ret = -(1 as libc::c_int);
        }
    }
    if ret < 0 as libc::c_int {
        chan_mark_dead(ssh, c);
    } else if ret == 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"channel_pre_dynamic\0"))
                .as_ptr(),
            1694 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: pre_dynamic: need more\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        (*c).io_want |= 0x1 as libc::c_int as libc::c_uint;
        if sshbuf_len((*c).output) != 0 {
            (*c).io_want |= 0x2 as libc::c_int as libc::c_uint;
        }
    } else {
        (*c).type_0 = 3 as libc::c_int;
        port_open_helper(
            ssh,
            c,
            b"direct-tcpip\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        );
    };
}
unsafe extern "C" fn rdynamic_close(mut ssh: *mut ssh, mut c: *mut Channel) {
    (*c).type_0 = 4 as libc::c_int;
    channel_force_close(ssh, c, 0 as libc::c_int);
}
unsafe extern "C" fn channel_before_prepare_io_rdynamic(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut p: *const u_char = 0 as *const u_char;
    let mut have: u_int = 0;
    let mut len: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    have = sshbuf_len((*c).output) as u_int;
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 35], &[libc::c_char; 35]>(
            b"channel_before_prepare_io_rdynamic\0",
        ))
        .as_ptr(),
        1723 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: pre_rdynamic: have %d\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        have,
    );
    if (*c).flags & 0x8 as libc::c_int != 0 {
        r = sshbuf_consume((*c).output, have as size_t);
        if r != 0 as libc::c_int {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 35], &[libc::c_char; 35]>(
                    b"channel_before_prepare_io_rdynamic\0",
                ))
                .as_ptr(),
                1728 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %d: consume\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
        rdynamic_close(ssh, c);
        return;
    }
    if have < 3 as libc::c_int as libc::c_uint {
        return;
    }
    p = sshbuf_ptr((*c).output);
    match *p.offset(0 as libc::c_int as isize) as libc::c_int {
        4 => {
            ret = channel_decode_socks4(c, (*c).output, (*c).input);
        }
        5 => {
            ret = channel_decode_socks5(c, (*c).output, (*c).input);
        }
        _ => {
            ret = -(1 as libc::c_int);
        }
    }
    if ret < 0 as libc::c_int {
        rdynamic_close(ssh, c);
    } else if ret == 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 35], &[libc::c_char; 35]>(
                b"channel_before_prepare_io_rdynamic\0",
            ))
            .as_ptr(),
            1752 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: pre_rdynamic: need more\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        len = sshbuf_len((*c).input) as u_int;
        if len > 0 as libc::c_int as libc::c_uint && len < (*c).remote_window {
            r = sshpkt_start(ssh, 94 as libc::c_int as u_char);
            if r != 0 as libc::c_int
                || {
                    r = sshpkt_put_u32(ssh, (*c).remote_id);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_stringb(ssh, (*c).input);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_send(ssh);
                    r != 0 as libc::c_int
                }
            {
                sshfatal(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 35], &[libc::c_char; 35]>(
                        b"channel_before_prepare_io_rdynamic\0",
                    ))
                    .as_ptr(),
                    1760 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"channel %i: rdynamic\0" as *const u8 as *const libc::c_char,
                    (*c).self_0,
                );
            }
            r = sshbuf_consume((*c).input, len as size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 35], &[libc::c_char; 35]>(
                        b"channel_before_prepare_io_rdynamic\0",
                    ))
                    .as_ptr(),
                    1763 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"channel %d: consume\0" as *const u8 as *const libc::c_char,
                    (*c).self_0,
                );
            }
            (*c).remote_window =
                ((*c).remote_window as libc::c_uint).wrapping_sub(len) as u_int as u_int;
        }
    } else if rdynamic_connect_finish(ssh, c) < 0 as libc::c_int {
        rdynamic_close(ssh, c);
    }
}
unsafe extern "C" fn channel_post_x11_listener(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut nc: *mut Channel = 0 as *mut Channel;
    let mut addr: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut r: libc::c_int = 0;
    let mut newsock: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    let mut remote_port: libc::c_int = 0;
    let mut addrlen: socklen_t = 0;
    let mut buf: [libc::c_char; 16384] = [0; 16384];
    let mut remote_ipaddr: *mut libc::c_char = 0 as *mut libc::c_char;
    if (*c).io_ready & 0x10 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        return;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"channel_post_x11_listener\0"))
            .as_ptr(),
        1785 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"X11 connection requested.\0" as *const u8 as *const libc::c_char,
    );
    addrlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    newsock = accept(
        (*c).sock,
        __SOCKADDR_ARG {
            __sockaddr__: &mut addr as *mut sockaddr_storage as *mut sockaddr,
        },
        &mut addrlen,
    );
    if (*c).single_connection != 0 {
        oerrno = *__errno_location();
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"channel_post_x11_listener\0",
            ))
            .as_ptr(),
            1790 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"single_connection: closing X11 listener.\0" as *const u8 as *const libc::c_char,
        );
        channel_close_fd(ssh, c, &mut (*c).sock);
        chan_mark_dead(ssh, c);
        *__errno_location() = oerrno;
    }
    if newsock == -(1 as libc::c_int) {
        if *__errno_location() != 4 as libc::c_int
            && *__errno_location() != 11 as libc::c_int
            && *__errno_location() != 103 as libc::c_int
        {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"channel_post_x11_listener\0",
                ))
                .as_ptr(),
                1798 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"accept: %.100s\0" as *const u8 as *const libc::c_char,
                strerror(*__errno_location()),
            );
        }
        if *__errno_location() == 24 as libc::c_int || *__errno_location() == 23 as libc::c_int {
            (*c).notbefore = monotime() + 1 as libc::c_int as libc::c_long;
        }
        return;
    }
    set_nodelay(newsock);
    remote_ipaddr = get_peer_ipaddr(newsock);
    remote_port = get_peer_port(newsock);
    snprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 16384]>() as libc::c_ulong,
        b"X11 connection from %.200s port %d\0" as *const u8 as *const libc::c_char,
        remote_ipaddr,
        remote_port,
    );
    nc = channel_new(
        ssh,
        b"x11-connection\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        3 as libc::c_int,
        newsock,
        newsock,
        -(1 as libc::c_int),
        (*c).local_window_max,
        (*c).local_maxpacket,
        0 as libc::c_int,
        buf.as_mut_ptr(),
        1 as libc::c_int,
    );
    open_preamble(
        ssh,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"channel_post_x11_listener\0"))
            .as_ptr(),
        nc,
        b"x11\0" as *const u8 as *const libc::c_char,
    );
    r = sshpkt_put_cstring(ssh, remote_ipaddr as *const libc::c_void);
    if r != 0 as libc::c_int || {
        r = sshpkt_put_u32(ssh, remote_port as u_int32_t);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"channel_post_x11_listener\0",
            ))
            .as_ptr(),
            1815 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i: reply\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    r = sshpkt_send(ssh);
    if r != 0 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"channel_post_x11_listener\0",
            ))
            .as_ptr(),
            1818 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i: send\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    free(remote_ipaddr as *mut libc::c_void);
}
unsafe extern "C" fn port_open_helper(
    mut ssh: *mut ssh,
    mut c: *mut Channel,
    mut rtype: *mut libc::c_char,
) {
    let mut local_ipaddr: *mut libc::c_char = get_local_ipaddr((*c).sock);
    let mut local_port: libc::c_int = if (*c).sock == -(1 as libc::c_int) {
        65536 as libc::c_int
    } else {
        get_local_port((*c).sock)
    };
    let mut remote_ipaddr: *mut libc::c_char = get_peer_ipaddr((*c).sock);
    let mut remote_port: libc::c_int = get_peer_port((*c).sock);
    let mut r: libc::c_int = 0;
    if remote_port == -(1 as libc::c_int) {
        free(remote_ipaddr as *mut libc::c_void);
        remote_ipaddr = xstrdup(b"127.0.0.1\0" as *const u8 as *const libc::c_char);
        remote_port = 65535 as libc::c_int;
    }
    free((*c).remote_name as *mut libc::c_void);
    xasprintf(
        &mut (*c).remote_name as *mut *mut libc::c_char,
        b"%s: listening port %d for %.100s port %d, connect from %.200s port %d to %.100s port %d\0"
            as *const u8 as *const libc::c_char,
        rtype,
        (*c).listening_port,
        (*c).path,
        (*c).host_port,
        remote_ipaddr,
        remote_port,
        local_ipaddr,
        local_port,
    );
    open_preamble(
        ssh,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"port_open_helper\0")).as_ptr(),
        c,
        rtype,
    );
    if strcmp(rtype, b"direct-tcpip\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        r = sshpkt_put_cstring(ssh, (*c).path as *const libc::c_void);
        if r != 0 as libc::c_int || {
            r = sshpkt_put_u32(ssh, (*c).host_port as u_int32_t);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"port_open_helper\0"))
                    .as_ptr(),
                1850 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i: reply\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
    } else if strcmp(
        rtype,
        b"direct-streamlocal@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        r = sshpkt_put_cstring(ssh, (*c).path as *const libc::c_void);
        if r != 0 as libc::c_int {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"port_open_helper\0"))
                    .as_ptr(),
                1854 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i: reply\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
    } else if strcmp(
        rtype,
        b"forwarded-streamlocal@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        r = sshpkt_put_cstring(ssh, (*c).path as *const libc::c_void);
        if r != 0 as libc::c_int {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"port_open_helper\0"))
                    .as_ptr(),
                1858 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i: reply\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
    } else {
        r = sshpkt_put_cstring(ssh, (*c).path as *const libc::c_void);
        if r != 0 as libc::c_int || {
            r = sshpkt_put_u32(ssh, local_port as u_int32_t);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"port_open_helper\0"))
                    .as_ptr(),
                1863 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i: reply\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
    }
    if strcmp(
        rtype,
        b"forwarded-streamlocal@openssh.com\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        r = sshpkt_put_cstring(
            ssh,
            b"\0" as *const u8 as *const libc::c_char as *const libc::c_void,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"port_open_helper\0"))
                    .as_ptr(),
                1868 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i: reply\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
    } else {
        r = sshpkt_put_cstring(ssh, remote_ipaddr as *const libc::c_void);
        if r != 0 as libc::c_int || {
            r = sshpkt_put_u32(ssh, remote_port as u_int);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"port_open_helper\0"))
                    .as_ptr(),
                1873 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i: reply\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
    }
    r = sshpkt_send(ssh);
    if r != 0 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"port_open_helper\0"))
                .as_ptr(),
            1876 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i: send\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    free(remote_ipaddr as *mut libc::c_void);
    free(local_ipaddr as *mut libc::c_void);
}
pub unsafe extern "C" fn channel_set_x11_refuse_time(mut ssh: *mut ssh, mut refuse_time: time_t) {
    (*(*ssh).chanctxt).x11_refuse_time = refuse_time;
}
unsafe extern "C" fn channel_post_port_listener(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut nc: *mut Channel = 0 as *mut Channel;
    let mut addr: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut newsock: libc::c_int = 0;
    let mut nextstate: libc::c_int = 0;
    let mut addrlen: socklen_t = 0;
    let mut rtype: *mut libc::c_char = 0 as *mut libc::c_char;
    if (*c).io_ready & 0x10 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        return;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
            b"channel_post_port_listener\0",
        ))
        .as_ptr(),
        1903 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Connection to port %d forwarding to %.100s port %d requested.\0" as *const u8
            as *const libc::c_char,
        (*c).listening_port,
        (*c).path,
        (*c).host_port,
    );
    if (*c).type_0 == 11 as libc::c_int {
        nextstate = 3 as libc::c_int;
        rtype = b"forwarded-tcpip\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    } else if (*c).type_0 == 19 as libc::c_int {
        nextstate = 3 as libc::c_int;
        rtype = b"forwarded-streamlocal@openssh.com\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char;
    } else if (*c).host_port == -(2 as libc::c_int) {
        nextstate = 3 as libc::c_int;
        rtype = b"direct-streamlocal@openssh.com\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char;
    } else if (*c).host_port == 0 as libc::c_int {
        nextstate = 13 as libc::c_int;
        rtype = b"dynamic-tcpip\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    } else {
        nextstate = 3 as libc::c_int;
        rtype = b"direct-tcpip\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    addrlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    newsock = accept(
        (*c).sock,
        __SOCKADDR_ARG {
            __sockaddr__: &mut addr as *mut sockaddr_storage as *mut sockaddr,
        },
        &mut addrlen,
    );
    if newsock == -(1 as libc::c_int) {
        if *__errno_location() != 4 as libc::c_int
            && *__errno_location() != 11 as libc::c_int
            && *__errno_location() != 103 as libc::c_int
        {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                    b"channel_post_port_listener\0",
                ))
                .as_ptr(),
                1927 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"accept: %.100s\0" as *const u8 as *const libc::c_char,
                strerror(*__errno_location()),
            );
        }
        if *__errno_location() == 24 as libc::c_int || *__errno_location() == 23 as libc::c_int {
            (*c).notbefore = monotime() + 1 as libc::c_int as libc::c_long;
        }
        return;
    }
    if (*c).host_port != -(2 as libc::c_int) {
        set_nodelay(newsock);
    }
    nc = channel_new(
        ssh,
        rtype,
        nextstate,
        newsock,
        newsock,
        -(1 as libc::c_int),
        (*c).local_window_max,
        (*c).local_maxpacket,
        0 as libc::c_int,
        rtype,
        1 as libc::c_int,
    );
    (*nc).listening_port = (*c).listening_port;
    (*nc).host_port = (*c).host_port;
    if !((*c).path).is_null() {
        (*nc).path = xstrdup((*c).path);
    }
    if nextstate != 13 as libc::c_int {
        port_open_helper(ssh, nc, rtype);
    }
}
unsafe extern "C" fn channel_post_auth_listener(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut nc: *mut Channel = 0 as *mut Channel;
    let mut r: libc::c_int = 0;
    let mut newsock: libc::c_int = 0;
    let mut addr: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut addrlen: socklen_t = 0;
    if (*c).io_ready & 0x10 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        return;
    }
    addrlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    newsock = accept(
        (*c).sock,
        __SOCKADDR_ARG {
            __sockaddr__: &mut addr as *mut sockaddr_storage as *mut sockaddr,
        },
        &mut addrlen,
    );
    if newsock == -(1 as libc::c_int) {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"channel_post_auth_listener\0",
            ))
            .as_ptr(),
            1963 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"accept from auth socket: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        if *__errno_location() == 24 as libc::c_int || *__errno_location() == 23 as libc::c_int {
            (*c).notbefore = monotime() + 1 as libc::c_int as libc::c_long;
        }
        return;
    }
    nc = channel_new(
        ssh,
        b"agent-connection\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        3 as libc::c_int,
        newsock,
        newsock,
        -(1 as libc::c_int),
        (*c).local_window_max,
        (*c).local_maxpacket,
        0 as libc::c_int,
        b"accepted auth socket\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    open_preamble(
        ssh,
        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
            b"channel_post_auth_listener\0",
        ))
        .as_ptr(),
        nc,
        b"auth-agent@openssh.com\0" as *const u8 as *const libc::c_char,
    );
    r = sshpkt_send(ssh);
    if r != 0 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"channel_post_auth_listener\0",
            ))
            .as_ptr(),
            1974 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
}
unsafe extern "C" fn channel_post_connecting(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut err: libc::c_int = 0 as libc::c_int;
    let mut sock: libc::c_int = 0;
    let mut isopen: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut sz: socklen_t = ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t;
    if (*c).io_ready & 0x20 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        return;
    }
    if (*c).have_remote_id == 0 {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"channel_post_connecting\0",
            ))
            .as_ptr(),
            1986 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d: no remote id\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    isopen = ((*c).type_0 == 22 as libc::c_int) as libc::c_int;
    if getsockopt(
        (*c).sock,
        1 as libc::c_int,
        4 as libc::c_int,
        &mut err as *mut libc::c_int as *mut libc::c_void,
        &mut sz,
    ) == -(1 as libc::c_int)
    {
        err = *__errno_location();
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"channel_post_connecting\0",
            ))
            .as_ptr(),
            1992 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"getsockopt SO_ERROR failed\0" as *const u8 as *const libc::c_char,
        );
    }
    if err == 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"channel_post_connecting\0",
            ))
            .as_ptr(),
            1998 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"channel %d: connected to %s port %d\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            (*c).connect_ctx.host,
            (*c).connect_ctx.port,
        );
        channel_connect_ctx_free(&mut (*c).connect_ctx);
        (*c).type_0 = 4 as libc::c_int;
        (*c).lastused = monotime();
        if !(isopen != 0) {
            r = sshpkt_start(ssh, 91 as libc::c_int as u_char);
            if r != 0 as libc::c_int
                || {
                    r = sshpkt_put_u32(ssh, (*c).remote_id);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_u32(ssh, (*c).self_0 as u_int32_t);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_u32(ssh, (*c).local_window);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_u32(ssh, (*c).local_maxpacket);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_send(ssh);
                    r != 0 as libc::c_int
                }
            {
                sshfatal(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"channel_post_connecting\0",
                    ))
                    .as_ptr(),
                    2012 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"channel %i open confirm\0" as *const u8 as *const libc::c_char,
                    (*c).self_0,
                );
            }
        }
        return;
    }
    if err == 4 as libc::c_int || err == 11 as libc::c_int || err == 115 as libc::c_int {
        return;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"channel_post_connecting\0"))
            .as_ptr(),
        2020 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"channel %d: connection failed: %s\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        strerror(err),
    );
    sock = connect_next(&mut (*c).connect_ctx);
    if sock == -(1 as libc::c_int) {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"channel_post_connecting\0",
            ))
            .as_ptr(),
            2026 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"connect_to %.100s port %d: failed.\0" as *const u8 as *const libc::c_char,
            (*c).connect_ctx.host,
            (*c).connect_ctx.port,
        );
        channel_connect_ctx_free(&mut (*c).connect_ctx);
        if isopen != 0 {
            rdynamic_close(ssh, c);
        } else {
            r = sshpkt_start(ssh, 92 as libc::c_int as u_char);
            if r != 0 as libc::c_int
                || {
                    r = sshpkt_put_u32(ssh, (*c).remote_id);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_u32(ssh, 2 as libc::c_int as u_int32_t);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_cstring(ssh, strerror(err) as *const libc::c_void);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_cstring(
                        ssh,
                        b"\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                    );
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_send(ssh);
                    r != 0 as libc::c_int
                }
            {
                sshfatal(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"channel_post_connecting\0",
                    ))
                    .as_ptr(),
                    2039 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"channel %i: failure\0" as *const u8 as *const libc::c_char,
                    (*c).self_0,
                );
            }
            chan_mark_dead(ssh, c);
        }
    }
    close((*c).sock);
    (*c).wfd = sock;
    (*c).rfd = (*c).wfd;
    (*c).sock = (*c).rfd;
}
unsafe extern "C" fn channel_handle_rfd(mut ssh: *mut ssh, mut c: *mut Channel) -> libc::c_int {
    let mut buf: [libc::c_char; 16384] = [0; 16384];
    let mut len: ssize_t = 0;
    let mut r: libc::c_int = 0;
    let mut force: libc::c_int = 0;
    let mut nr: size_t = 0 as libc::c_int as size_t;
    let mut have: size_t = 0;
    let mut avail: size_t = 0;
    let mut maxlen: size_t = (32 as libc::c_int * 1024 as libc::c_int) as size_t;
    let mut pty_zeroread: libc::c_int = 0 as libc::c_int;
    force = ((*c).isatty != 0
        && (*c).detach_close != 0
        && (*c).istate != 3 as libc::c_int as libc::c_uint) as libc::c_int;
    if force == 0
        && (*c).io_ready & 0x1 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint
    {
        return 1 as libc::c_int;
    }
    avail = sshbuf_avail((*c).input);
    if avail == 0 as libc::c_int as libc::c_ulong {
        return 1 as libc::c_int;
    }
    if pty_zeroread == 0 && ((*c).input_filter).is_none() && (*c).datagram == 0 {
        if (*c).type_0 == 4 as libc::c_int {
            have = sshbuf_len((*c).input);
            if have >= (*c).remote_window as libc::c_ulong {
                return 1 as libc::c_int;
            }
            if maxlen > ((*c).remote_window as libc::c_ulong).wrapping_sub(have) {
                maxlen = ((*c).remote_window as libc::c_ulong).wrapping_sub(have);
            }
        }
        if maxlen > avail {
            maxlen = avail;
        }
        r = sshbuf_read((*c).rfd, (*c).input, maxlen, &mut nr);
        if r != 0 as libc::c_int {
            if *__errno_location() == 4 as libc::c_int
                || force == 0
                    && (*__errno_location() == 11 as libc::c_int
                        || *__errno_location() == 11 as libc::c_int)
            {
                return 1 as libc::c_int;
            }
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"channel_handle_rfd\0",
                ))
                .as_ptr(),
                2089 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"channel %d: read failed rfd %d maxlen %zu: %s\0" as *const u8
                    as *const libc::c_char,
                (*c).self_0,
                (*c).rfd,
                maxlen,
                ssh_err(r),
            );
        } else {
            if nr != 0 as libc::c_int as libc::c_ulong {
                (*c).lastused = monotime();
            }
            return 1 as libc::c_int;
        }
    } else {
        *__errno_location() = 0 as libc::c_int;
        len = read(
            (*c).rfd,
            buf.as_mut_ptr() as *mut libc::c_void,
            ::core::mem::size_of::<[libc::c_char; 16384]>() as libc::c_ulong,
        );
        if pty_zeroread != 0
            && len == 0 as libc::c_int as libc::c_long
            && *__errno_location() != 0 as libc::c_int
        {
            len = -(1 as libc::c_int) as ssize_t;
        }
        if len == -(1 as libc::c_int) as libc::c_long
            && (*__errno_location() == 4 as libc::c_int
                || (*__errno_location() == 11 as libc::c_int
                    || *__errno_location() == 11 as libc::c_int)
                    && force == 0)
        {
            return 1 as libc::c_int;
        }
        if len < 0 as libc::c_int as libc::c_long
            || pty_zeroread == 0 && len == 0 as libc::c_int as libc::c_long
        {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"channel_handle_rfd\0",
                ))
                .as_ptr(),
                2108 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"channel %d: read<=0 rfd %d len %zd: %s\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
                (*c).rfd,
                len,
                if len == 0 as libc::c_int as libc::c_long {
                    b"closed\0" as *const u8 as *const libc::c_char
                } else {
                    strerror(*__errno_location()) as *const libc::c_char
                },
            );
        } else {
            (*c).lastused = monotime();
            if ((*c).input_filter).is_some() {
                if ((*c).input_filter).expect("non-null function pointer")(
                    ssh,
                    c,
                    buf.as_mut_ptr(),
                    len as libc::c_int,
                ) == -(1 as libc::c_int)
                {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"channel_handle_rfd\0",
                        ))
                        .as_ptr(),
                        2122 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        0 as *const libc::c_char,
                        b"channel %d: filter stops\0" as *const u8 as *const libc::c_char,
                        (*c).self_0,
                    );
                    chan_read_failed(ssh, c);
                }
            } else if (*c).datagram != 0 {
                r = sshbuf_put_string(
                    (*c).input,
                    buf.as_mut_ptr() as *const libc::c_void,
                    len as size_t,
                );
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"channel_handle_rfd\0",
                        ))
                        .as_ptr(),
                        2127 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"channel %i: put datagram\0" as *const u8 as *const libc::c_char,
                        (*c).self_0,
                    );
                }
            } else {
                r = sshbuf_put(
                    (*c).input,
                    buf.as_mut_ptr() as *const libc::c_void,
                    len as size_t,
                );
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"channel_handle_rfd\0",
                        ))
                        .as_ptr(),
                        2129 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"channel %i: put data\0" as *const u8 as *const libc::c_char,
                        (*c).self_0,
                    );
                }
            }
            return 1 as libc::c_int;
        }
    }
    if (*c).type_0 != 4 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"channel_handle_rfd\0"))
                .as_ptr(),
            2111 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: not open\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        chan_mark_dead(ssh, c);
        return -(1 as libc::c_int);
    } else {
        chan_read_failed(ssh, c);
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn channel_handle_wfd(mut ssh: *mut ssh, mut c: *mut Channel) -> libc::c_int {
    let mut current_block: u64;
    let mut tio: termios = termios {
        c_iflag: 0,
        c_oflag: 0,
        c_cflag: 0,
        c_lflag: 0,
        c_line: 0,
        c_cc: [0; 32],
        c_ispeed: 0,
        c_ospeed: 0,
    };
    let mut data: *mut u_char = 0 as *mut u_char;
    let mut buf: *mut u_char = 0 as *mut u_char;
    let mut dlen: size_t = 0;
    let mut olen: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    if (*c).io_ready & 0x2 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        return 1 as libc::c_int;
    }
    if sshbuf_len((*c).output) == 0 as libc::c_int as libc::c_ulong {
        return 1 as libc::c_int;
    }
    olen = sshbuf_len((*c).output);
    if ((*c).output_filter).is_some() {
        buf =
            ((*c).output_filter).expect("non-null function pointer")(ssh, c, &mut data, &mut dlen);
        if buf.is_null() {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"channel_handle_wfd\0",
                ))
                .as_ptr(),
                2151 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"channel %d: filter stops\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
            if (*c).type_0 != 4 as libc::c_int {
                chan_mark_dead(ssh, c);
            } else {
                chan_write_failed(ssh, c);
            }
            return -(1 as libc::c_int);
        }
    } else if (*c).datagram != 0 {
        r = sshbuf_get_string((*c).output, &mut data, &mut dlen);
        if r != 0 as libc::c_int {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"channel_handle_wfd\0",
                ))
                .as_ptr(),
                2160 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i: get datagram\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
        buf = data;
    } else {
        data = sshbuf_mutable_ptr((*c).output);
        buf = data;
        dlen = sshbuf_len((*c).output);
    }
    if (*c).datagram != 0 {
        len = write((*c).wfd, buf as *const libc::c_void, dlen) as libc::c_int;
        free(data as *mut libc::c_void);
        if len == -(1 as libc::c_int)
            && (*__errno_location() == 4 as libc::c_int
                || *__errno_location() == 11 as libc::c_int
                || *__errno_location() == 11 as libc::c_int)
        {
            return 1 as libc::c_int;
        }
        if len <= 0 as libc::c_int {
            current_block = 3367960970728236482;
        } else {
            current_block = 10379427723606251154;
        }
    } else {
        len = write((*c).wfd, buf as *const libc::c_void, dlen) as libc::c_int;
        if len == -(1 as libc::c_int)
            && (*__errno_location() == 4 as libc::c_int
                || *__errno_location() == 11 as libc::c_int
                || *__errno_location() == 11 as libc::c_int)
        {
            return 1 as libc::c_int;
        }
        if len <= 0 as libc::c_int {
            current_block = 3367960970728236482;
        } else {
            (*c).lastused = monotime();
            if (*c).isatty != 0
                && dlen >= 1 as libc::c_int as libc::c_ulong
                && *buf.offset(0 as libc::c_int as isize) as libc::c_int != '\r' as i32
            {
                if tcgetattr((*c).wfd, &mut tio) == 0 as libc::c_int
                    && tio.c_lflag & 0o10 as libc::c_int as libc::c_uint == 0
                    && tio.c_lflag & 0o2 as libc::c_int as libc::c_uint != 0
                {
                    r = sshpkt_msg_ignore(ssh, (4 as libc::c_int + len) as u_int);
                    if r != 0 as libc::c_int || {
                        r = sshpkt_send(ssh);
                        r != 0 as libc::c_int
                    } {
                        sshfatal(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                b"channel_handle_wfd\0",
                            ))
                            .as_ptr(),
                            2213 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"channel %i: ignore\0" as *const u8 as *const libc::c_char,
                            (*c).self_0,
                        );
                    }
                }
            }
            r = sshbuf_consume((*c).output, len as size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"channel_handle_wfd\0",
                    ))
                    .as_ptr(),
                    2218 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"channel %i: consume\0" as *const u8 as *const libc::c_char,
                    (*c).self_0,
                );
            }
            current_block = 10379427723606251154;
        }
    }
    match current_block {
        10379427723606251154 => {
            (*c).local_consumed = ((*c).local_consumed as libc::c_ulong)
                .wrapping_add(olen.wrapping_sub(sshbuf_len((*c).output)))
                as u_int as u_int;
            return 1 as libc::c_int;
        }
        _ => {
            if (*c).type_0 != 4 as libc::c_int {
                sshlog(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"channel_handle_wfd\0",
                    ))
                    .as_ptr(),
                    2192 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"channel %d: not open\0" as *const u8 as *const libc::c_char,
                    (*c).self_0,
                );
                chan_mark_dead(ssh, c);
                return -(1 as libc::c_int);
            } else {
                chan_write_failed(ssh, c);
            }
            return -(1 as libc::c_int);
        }
    };
}
unsafe extern "C" fn channel_handle_efd_write(
    mut ssh: *mut ssh,
    mut c: *mut Channel,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut len: ssize_t = 0;
    if (*c).io_ready & 0x8 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        return 1 as libc::c_int;
    }
    if sshbuf_len((*c).extended) == 0 as libc::c_int as libc::c_ulong {
        return 1 as libc::c_int;
    }
    len = write(
        (*c).efd,
        sshbuf_ptr((*c).extended) as *const libc::c_void,
        sshbuf_len((*c).extended),
    );
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"channel_handle_efd_write\0"))
            .as_ptr(),
        2238 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: written %zd to efd %d\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        len,
        (*c).efd,
    );
    if len == -(1 as libc::c_int) as libc::c_long
        && (*__errno_location() == 4 as libc::c_int
            || *__errno_location() == 11 as libc::c_int
            || *__errno_location() == 11 as libc::c_int)
    {
        return 1 as libc::c_int;
    }
    if len <= 0 as libc::c_int as libc::c_long {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"channel_handle_efd_write\0",
            ))
            .as_ptr(),
            2243 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: closing write-efd %d\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            (*c).efd,
        );
        channel_close_fd(ssh, c, &mut (*c).efd);
    } else {
        r = sshbuf_consume((*c).extended, len as size_t);
        if r != 0 as libc::c_int {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"channel_handle_efd_write\0",
                ))
                .as_ptr(),
                2247 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i: consume\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
        (*c).local_consumed = ((*c).local_consumed as libc::c_long + len) as u_int;
        (*c).lastused = monotime();
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn channel_handle_efd_read(
    mut ssh: *mut ssh,
    mut c: *mut Channel,
) -> libc::c_int {
    let mut buf: [libc::c_char; 16384] = [0; 16384];
    let mut len: ssize_t = 0;
    let mut r: libc::c_int = 0;
    let mut force: libc::c_int = 0;
    force = ((*c).isatty != 0
        && (*c).detach_close != 0
        && (*c).istate != 3 as libc::c_int as libc::c_uint) as libc::c_int;
    if force == 0
        && (*c).io_ready & 0x4 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint
    {
        return 1 as libc::c_int;
    }
    len = read(
        (*c).efd,
        buf.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_char; 16384]>() as libc::c_ulong,
    );
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"channel_handle_efd_read\0"))
            .as_ptr(),
        2267 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: read %zd from efd %d\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        len,
        (*c).efd,
    );
    if len == -(1 as libc::c_int) as libc::c_long
        && (*__errno_location() == 4 as libc::c_int
            || (*__errno_location() == 11 as libc::c_int
                || *__errno_location() == 11 as libc::c_int)
                && force == 0)
    {
        return 1 as libc::c_int;
    }
    if len <= 0 as libc::c_int as libc::c_long {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"channel_handle_efd_read\0",
            ))
            .as_ptr(),
            2272 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: closing read-efd %d\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            (*c).efd,
        );
        channel_close_fd(ssh, c, &mut (*c).efd);
        return 1 as libc::c_int;
    }
    (*c).lastused = monotime();
    if (*c).extended_usage == 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"channel_handle_efd_read\0",
            ))
            .as_ptr(),
            2278 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"channel %d: discard efd\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    } else {
        r = sshbuf_put(
            (*c).extended,
            buf.as_mut_ptr() as *const libc::c_void,
            len as size_t,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"channel_handle_efd_read\0",
                ))
                .as_ptr(),
                2280 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i: append\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn channel_handle_efd(mut ssh: *mut ssh, mut c: *mut Channel) -> libc::c_int {
    if (*c).efd == -(1 as libc::c_int) {
        return 1 as libc::c_int;
    }
    if (*c).extended_usage == 2 as libc::c_int {
        return channel_handle_efd_write(ssh, c);
    } else if (*c).extended_usage == 1 as libc::c_int || (*c).extended_usage == 0 as libc::c_int {
        return channel_handle_efd_read(ssh, c);
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn channel_check_window(mut ssh: *mut ssh, mut c: *mut Channel) -> libc::c_int {
    let mut r: libc::c_int = 0;
    if (*c).type_0 == 4 as libc::c_int
        && (*c).flags & (0x1 as libc::c_int | 0x2 as libc::c_int) == 0
        && (((*c).local_window_max).wrapping_sub((*c).local_window)
            > ((*c).local_maxpacket).wrapping_mul(3 as libc::c_int as libc::c_uint)
            || (*c).local_window
                < ((*c).local_window_max).wrapping_div(2 as libc::c_int as libc::c_uint))
        && (*c).local_consumed > 0 as libc::c_int as libc::c_uint
    {
        if (*c).have_remote_id == 0 {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"channel_check_window\0",
                ))
                .as_ptr(),
                2313 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"channel %d: no remote id\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
        r = sshpkt_start(ssh, 93 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshpkt_put_u32(ssh, (*c).remote_id);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_put_u32(ssh, (*c).local_consumed);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_send(ssh);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"channel_check_window\0",
                ))
                .as_ptr(),
                2319 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"channel_check_window\0"))
                .as_ptr(),
            2322 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: window %d sent adjust %d\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            (*c).local_window,
            (*c).local_consumed,
        );
        (*c).local_window =
            ((*c).local_window as libc::c_uint).wrapping_add((*c).local_consumed) as u_int as u_int;
        (*c).local_consumed = 0 as libc::c_int as u_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn channel_post_open(mut ssh: *mut ssh, mut c: *mut Channel) {
    channel_handle_rfd(ssh, c);
    channel_handle_wfd(ssh, c);
    channel_handle_efd(ssh, c);
    channel_check_window(ssh, c);
}
unsafe extern "C" fn read_mux(mut ssh: *mut ssh, mut c: *mut Channel, mut need: u_int) -> u_int {
    let mut buf: [libc::c_char; 16384] = [0; 16384];
    let mut len: ssize_t = 0;
    let mut rlen: u_int = 0;
    let mut r: libc::c_int = 0;
    if sshbuf_len((*c).input) < need as libc::c_ulong {
        rlen = (need as libc::c_ulong).wrapping_sub(sshbuf_len((*c).input)) as u_int;
        len = read(
            (*c).rfd,
            buf.as_mut_ptr() as *mut libc::c_void,
            (if rlen < (16 as libc::c_int * 1024 as libc::c_int) as libc::c_uint {
                rlen
            } else {
                (16 as libc::c_int * 1024 as libc::c_int) as libc::c_uint
            }) as size_t,
        );
        if len == -(1 as libc::c_int) as libc::c_long
            && (*__errno_location() == 4 as libc::c_int || *__errno_location() == 11 as libc::c_int)
        {
            return sshbuf_len((*c).input) as u_int;
        }
        if len <= 0 as libc::c_int as libc::c_long {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"read_mux\0")).as_ptr(),
                2353 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"channel %d: ctl read<=0 rfd %d len %zd\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
                (*c).rfd,
                len,
            );
            chan_read_failed(ssh, c);
            return 0 as libc::c_int as u_int;
        } else {
            r = sshbuf_put(
                (*c).input,
                buf.as_mut_ptr() as *const libc::c_void,
                len as size_t,
            );
            if r != 0 as libc::c_int {
                sshfatal(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"read_mux\0"))
                        .as_ptr(),
                    2357 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"channel %i: append\0" as *const u8 as *const libc::c_char,
                    (*c).self_0,
                );
            }
        }
    }
    return sshbuf_len((*c).input) as u_int;
}
unsafe extern "C" fn channel_post_mux_client_read(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut need: u_int = 0;
    if (*c).io_ready & 0x1 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        return;
    }
    if (*c).istate != 0 as libc::c_int as libc::c_uint
        && (*c).istate != 1 as libc::c_int as libc::c_uint
    {
        return;
    }
    if (*c).mux_pause != 0 {
        return;
    }
    if read_mux(ssh, c, 4 as libc::c_int as u_int) < 4 as libc::c_int as libc::c_uint {
        return;
    }
    need = (*(sshbuf_ptr((*c).input)).offset(0 as libc::c_int as isize) as u_int32_t)
        << 24 as libc::c_int
        | (*(sshbuf_ptr((*c).input)).offset(1 as libc::c_int as isize) as u_int32_t)
            << 16 as libc::c_int
        | (*(sshbuf_ptr((*c).input)).offset(2 as libc::c_int as isize) as u_int32_t)
            << 8 as libc::c_int
        | *(sshbuf_ptr((*c).input)).offset(3 as libc::c_int as isize) as u_int32_t;
    if need > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_uint {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"channel_post_mux_client_read\0",
            ))
            .as_ptr(),
            2385 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: packet too big %u > %u\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            256 as libc::c_int * 1024 as libc::c_int,
            need,
        );
        chan_rcvd_oclose(ssh, c);
        return;
    }
    if read_mux(ssh, c, need.wrapping_add(4 as libc::c_int as libc::c_uint))
        < need.wrapping_add(4 as libc::c_int as libc::c_uint)
    {
        return;
    }
    if ((*c).mux_rcb).expect("non-null function pointer")(ssh, c) != 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"channel_post_mux_client_read\0",
            ))
            .as_ptr(),
            2392 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"channel %d: mux_rcb failed\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        chan_mark_dead(ssh, c);
        return;
    }
}
unsafe extern "C" fn channel_post_mux_client_write(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut len: ssize_t = 0;
    let mut r: libc::c_int = 0;
    if (*c).io_ready & 0x2 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        return;
    }
    if sshbuf_len((*c).output) == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    len = write(
        (*c).wfd,
        sshbuf_ptr((*c).output) as *const libc::c_void,
        sshbuf_len((*c).output),
    );
    if len == -(1 as libc::c_int) as libc::c_long
        && (*__errno_location() == 4 as libc::c_int || *__errno_location() == 11 as libc::c_int)
    {
        return;
    }
    if len <= 0 as libc::c_int as libc::c_long {
        chan_mark_dead(ssh, c);
        return;
    }
    r = sshbuf_consume((*c).output, len as size_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"channel_post_mux_client_write\0",
            ))
            .as_ptr(),
            2417 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i: consume\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
}
unsafe extern "C" fn channel_post_mux_client(mut ssh: *mut ssh, mut c: *mut Channel) {
    channel_post_mux_client_read(ssh, c);
    channel_post_mux_client_write(ssh, c);
}
unsafe extern "C" fn channel_post_mux_listener(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut nc: *mut Channel = 0 as *mut Channel;
    let mut addr: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut addrlen: socklen_t = 0;
    let mut newsock: libc::c_int = 0;
    let mut euid: uid_t = 0;
    let mut egid: gid_t = 0;
    if (*c).io_ready & 0x10 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
        return;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"channel_post_mux_listener\0"))
            .as_ptr(),
        2440 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"multiplexing control connection\0" as *const u8 as *const libc::c_char,
    );
    memset(
        &mut addr as *mut sockaddr_storage as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong,
    );
    addrlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    newsock = accept(
        (*c).sock,
        __SOCKADDR_ARG {
            __sockaddr__: &mut addr as *mut sockaddr_storage as *mut sockaddr,
        },
        &mut addrlen,
    );
    if newsock == -(1 as libc::c_int) {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"channel_post_mux_listener\0",
            ))
            .as_ptr(),
            2449 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"accept: %s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        if *__errno_location() == 24 as libc::c_int || *__errno_location() == 23 as libc::c_int {
            (*c).notbefore = monotime() + 1 as libc::c_int as libc::c_long;
        }
        return;
    }
    if getpeereid(newsock, &mut euid, &mut egid) == -(1 as libc::c_int) {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"channel_post_mux_listener\0",
            ))
            .as_ptr(),
            2456 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"getpeereid failed: %s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        close(newsock);
        return;
    }
    if euid != 0 as libc::c_int as libc::c_uint && getuid() != euid {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"channel_post_mux_listener\0",
            ))
            .as_ptr(),
            2462 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"multiplex uid mismatch: peer euid %u != uid %u\0" as *const u8 as *const libc::c_char,
            euid,
            getuid(),
        );
        close(newsock);
        return;
    }
    nc = channel_new(
        ssh,
        b"mux-control\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        16 as libc::c_int,
        newsock,
        newsock,
        -(1 as libc::c_int),
        (*c).local_window_max,
        (*c).local_maxpacket,
        0 as libc::c_int,
        b"mux-control\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    (*nc).mux_rcb = (*c).mux_rcb;
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"channel_post_mux_listener\0"))
            .as_ptr(),
        2470 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"new mux channel %d fd %d\0" as *const u8 as *const libc::c_char,
        (*nc).self_0,
        (*nc).sock,
    );
    ((*nc).mux_rcb).expect("non-null function pointer")(ssh, nc);
    (*nc).flags |= 0x10 as libc::c_int;
}
unsafe extern "C" fn channel_handler_init(mut sc: *mut ssh_channels) {
    let mut pre: *mut Option<chan_fn> = 0 as *mut Option<chan_fn>;
    let mut post: *mut Option<chan_fn> = 0 as *mut Option<chan_fn>;
    pre = calloc(
        23 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<Option<chan_fn>>() as libc::c_ulong,
    ) as *mut Option<chan_fn>;
    if pre.is_null() || {
        post = calloc(
            23 as libc::c_int as libc::c_ulong,
            ::core::mem::size_of::<Option<chan_fn>>() as libc::c_ulong,
        ) as *mut Option<chan_fn>;
        post.is_null()
    } {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"channel_handler_init\0"))
                .as_ptr(),
            2484 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"allocation failed\0" as *const u8 as *const libc::c_char,
        );
    }
    let ref mut fresh8 = *pre.offset(4 as libc::c_int as isize);
    *fresh8 = Some(channel_pre_open as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh9 = *pre.offset(7 as libc::c_int as isize);
    *fresh9 = Some(channel_pre_x11_open as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh10 = *pre.offset(2 as libc::c_int as isize);
    *fresh10 = Some(channel_pre_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh11 = *pre.offset(11 as libc::c_int as isize);
    *fresh11 = Some(channel_pre_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh12 = *pre.offset(18 as libc::c_int as isize);
    *fresh12 = Some(channel_pre_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh13 = *pre.offset(19 as libc::c_int as isize);
    *fresh13 = Some(channel_pre_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh14 = *pre.offset(1 as libc::c_int as isize);
    *fresh14 = Some(channel_pre_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh15 = *pre.offset(6 as libc::c_int as isize);
    *fresh15 = Some(channel_pre_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh16 = *pre.offset(12 as libc::c_int as isize);
    *fresh16 = Some(channel_pre_connecting as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh17 = *pre.offset(13 as libc::c_int as isize);
    *fresh17 = Some(channel_pre_dynamic as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh18 = *pre.offset(22 as libc::c_int as isize);
    *fresh18 = Some(channel_pre_connecting as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh19 = *pre.offset(15 as libc::c_int as isize);
    *fresh19 = Some(channel_pre_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh20 = *pre.offset(16 as libc::c_int as isize);
    *fresh20 = Some(channel_pre_mux_client as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh21 = *post.offset(4 as libc::c_int as isize);
    *fresh21 = Some(channel_post_open as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh22 = *post.offset(2 as libc::c_int as isize);
    *fresh22 =
        Some(channel_post_port_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh23 = *post.offset(11 as libc::c_int as isize);
    *fresh23 =
        Some(channel_post_port_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh24 = *post.offset(18 as libc::c_int as isize);
    *fresh24 =
        Some(channel_post_port_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh25 = *post.offset(19 as libc::c_int as isize);
    *fresh25 =
        Some(channel_post_port_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh26 = *post.offset(1 as libc::c_int as isize);
    *fresh26 =
        Some(channel_post_x11_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh27 = *post.offset(6 as libc::c_int as isize);
    *fresh27 =
        Some(channel_post_auth_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh28 = *post.offset(12 as libc::c_int as isize);
    *fresh28 = Some(channel_post_connecting as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh29 = *post.offset(13 as libc::c_int as isize);
    *fresh29 = Some(channel_post_open as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh30 = *post.offset(22 as libc::c_int as isize);
    *fresh30 = Some(channel_post_connecting as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh31 = *post.offset(15 as libc::c_int as isize);
    *fresh31 =
        Some(channel_post_mux_listener as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    let ref mut fresh32 = *post.offset(16 as libc::c_int as isize);
    *fresh32 = Some(channel_post_mux_client as unsafe extern "C" fn(*mut ssh, *mut Channel) -> ());
    (*sc).channel_pre = pre;
    (*sc).channel_post = post;
}
unsafe extern "C" fn channel_garbage_collect(mut ssh: *mut ssh, mut c: *mut Channel) {
    if c.is_null() {
        return;
    }
    if ((*c).detach_user).is_some() {
        if chan_is_dead(ssh, c, (*c).detach_close) == 0 {
            return;
        }
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"channel_garbage_collect\0",
            ))
            .as_ptr(),
            2527 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: gc: notify user\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        ((*c).detach_user).expect("non-null function pointer")(
            ssh,
            (*c).self_0,
            0 as libc::c_int,
            0 as *mut libc::c_void,
        );
        if ((*c).detach_user).is_some() {
            return;
        }
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"channel_garbage_collect\0",
            ))
            .as_ptr(),
            2532 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: gc: user detached\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    if chan_is_dead(ssh, c, 1 as libc::c_int) == 0 {
        return;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"channel_garbage_collect\0"))
            .as_ptr(),
        2536 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: garbage collecting\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
    );
    channel_free(ssh, c);
}
unsafe extern "C" fn channel_handler(
    mut ssh: *mut ssh,
    mut table: libc::c_int,
    mut timeout: *mut timespec,
) {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut ftab: *mut Option<chan_fn> = if table == CHAN_PRE as libc::c_int {
        (*sc).channel_pre
    } else {
        (*sc).channel_post
    };
    let mut i: u_int = 0;
    let mut oalloc: u_int = 0;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut now: time_t = 0;
    now = monotime();
    let mut current_block_19: u64;
    i = 0 as libc::c_int as u_int;
    oalloc = (*sc).channels_alloc;
    while i < oalloc {
        c = *((*sc).channels).offset(i as isize);
        if !c.is_null() {
            if !(ssh_packet_is_rekeying(ssh) != 0 && (*c).type_0 != 4 as libc::c_int) {
                if (*c).delayed != 0 {
                    if table == CHAN_PRE as libc::c_int {
                        (*c).delayed = 0 as libc::c_int;
                        current_block_19 = 11812396948646013369;
                    } else {
                        current_block_19 = 12675440807659640239;
                    }
                } else {
                    current_block_19 = 11812396948646013369;
                }
                match current_block_19 {
                    12675440807659640239 => {}
                    _ => {
                        if (*ftab.offset((*c).type_0 as isize)).is_some() {
                            if table == CHAN_PRE as libc::c_int
                                && (*c).type_0 == 4 as libc::c_int
                                && (*c).inactive_deadline != 0 as libc::c_int as libc::c_uint
                                && (*c).lastused != 0 as libc::c_int as libc::c_long
                                && now >= (*c).lastused + (*c).inactive_deadline as libc::c_long
                            {
                                sshlog(
                                    b"channels.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"channel_handler\0",
                                    ))
                                    .as_ptr(),
                                    2573 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_VERBOSE,
                                    0 as *const libc::c_char,
                                    b"channel %d: closing after %u seconds of inactivity\0"
                                        as *const u8
                                        as *const libc::c_char,
                                    (*c).self_0,
                                    (*c).inactive_deadline,
                                );
                                channel_force_close(ssh, c, 1 as libc::c_int);
                            } else if (*c).notbefore <= now {
                                (Some(
                                    (*ftab.offset((*c).type_0 as isize))
                                        .expect("non-null function pointer"),
                                ))
                                .expect("non-null function pointer")(
                                    ssh, c
                                );
                                if !timeout.is_null()
                                    && (*c).type_0 == 4 as libc::c_int
                                    && (*c).lastused != 0 as libc::c_int as libc::c_long
                                    && (*c).inactive_deadline != 0 as libc::c_int as libc::c_uint
                                {
                                    ptimeout_deadline_monotime(
                                        timeout,
                                        (*c).lastused + (*c).inactive_deadline as libc::c_long,
                                    );
                                }
                            } else if !timeout.is_null() {
                                ptimeout_deadline_monotime(timeout, (*c).notbefore);
                            }
                        }
                        channel_garbage_collect(ssh, c);
                    }
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn channel_before_prepare_io(mut ssh: *mut ssh) {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut i: u_int = 0;
    let mut oalloc: u_int = 0;
    i = 0 as libc::c_int as u_int;
    oalloc = (*sc).channels_alloc;
    while i < oalloc {
        c = *((*sc).channels).offset(i as isize);
        if !c.is_null() {
            if (*c).type_0 == 21 as libc::c_int {
                channel_before_prepare_io_rdynamic(ssh, c);
            }
        }
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn dump_channel_poll(
    mut _func: *const libc::c_char,
    mut _what: *const libc::c_char,
    mut _c: *mut Channel,
    mut _pollfd_offset: u_int,
    mut _pfd: *mut pollfd,
) {
}
unsafe extern "C" fn channel_prepare_pollfd(
    mut c: *mut Channel,
    mut next_pollfd: *mut u_int,
    mut pfd: *mut pollfd,
    mut npfd: u_int,
) {
    let mut ev: u_int = 0;
    let mut p: u_int = *next_pollfd;
    if c.is_null() {
        return;
    }
    if p.wrapping_add(4 as libc::c_int as libc::c_uint) > npfd {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"channel_prepare_pollfd\0",
            ))
            .as_ptr(),
            2648 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d: bad pfd offset %u (max %u)\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            p,
            npfd,
        );
    }
    (*c).pfds[3 as libc::c_int as usize] = -(1 as libc::c_int);
    (*c).pfds[2 as libc::c_int as usize] = (*c).pfds[3 as libc::c_int as usize];
    (*c).pfds[1 as libc::c_int as usize] = (*c).pfds[2 as libc::c_int as usize];
    (*c).pfds[0 as libc::c_int as usize] = (*c).pfds[1 as libc::c_int as usize];
    if (*c).rfd != -(1 as libc::c_int) {
        ev = 0 as libc::c_int as u_int;
        if (*c).io_want & 0x1 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint {
            ev |= 0x1 as libc::c_int as libc::c_uint;
        }
        if (*c).wfd == (*c).rfd {
            if (*c).io_want & 0x2 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
            {
                ev |= 0x4 as libc::c_int as libc::c_uint;
            }
        }
        if (*c).efd == (*c).rfd {
            if (*c).io_want & 0x4 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
            {
                ev |= 0x1 as libc::c_int as libc::c_uint;
            }
            if (*c).io_want & 0x8 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
            {
                ev |= 0x4 as libc::c_int as libc::c_uint;
            }
        }
        if (*c).sock == (*c).rfd {
            if (*c).io_want & 0x10 as libc::c_int as libc::c_uint
                != 0 as libc::c_int as libc::c_uint
            {
                ev |= 0x1 as libc::c_int as libc::c_uint;
            }
            if (*c).io_want & 0x20 as libc::c_int as libc::c_uint
                != 0 as libc::c_int as libc::c_uint
            {
                ev |= 0x4 as libc::c_int as libc::c_uint;
            }
        }
        if ev != 0 as libc::c_int as libc::c_uint {
            (*c).pfds[0 as libc::c_int as usize] = p as libc::c_int;
            (*pfd.offset(p as isize)).fd = (*c).rfd;
            (*pfd.offset(p as isize)).events = ev as libc::c_short;
            dump_channel_poll(
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"channel_prepare_pollfd\0",
                ))
                .as_ptr(),
                b"rfd\0" as *const u8 as *const libc::c_char,
                c,
                p,
                &mut *pfd.offset(p as isize),
            );
            p = p.wrapping_add(1);
            p;
        }
    }
    if (*c).wfd != -(1 as libc::c_int) && (*c).rfd != (*c).wfd {
        ev = 0 as libc::c_int as u_int;
        if (*c).io_want & 0x2 as libc::c_int as libc::c_uint != 0 {
            ev |= 0x4 as libc::c_int as libc::c_uint;
        }
        if ev != 0 as libc::c_int as libc::c_uint {
            (*c).pfds[1 as libc::c_int as usize] = p as libc::c_int;
            (*pfd.offset(p as isize)).fd = (*c).wfd;
            (*pfd.offset(p as isize)).events = ev as libc::c_short;
            dump_channel_poll(
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"channel_prepare_pollfd\0",
                ))
                .as_ptr(),
                b"wfd\0" as *const u8 as *const libc::c_char,
                c,
                p,
                &mut *pfd.offset(p as isize),
            );
            p = p.wrapping_add(1);
            p;
        }
    }
    if (*c).efd != -(1 as libc::c_int) && (*c).rfd != (*c).efd {
        ev = 0 as libc::c_int as u_int;
        if (*c).io_want & 0x4 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint {
            ev |= 0x1 as libc::c_int as libc::c_uint;
        }
        if (*c).io_want & 0x8 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint {
            ev |= 0x4 as libc::c_int as libc::c_uint;
        }
        if ev != 0 as libc::c_int as libc::c_uint {
            (*c).pfds[2 as libc::c_int as usize] = p as libc::c_int;
            (*pfd.offset(p as isize)).fd = (*c).efd;
            (*pfd.offset(p as isize)).events = ev as libc::c_short;
            dump_channel_poll(
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"channel_prepare_pollfd\0",
                ))
                .as_ptr(),
                b"efd\0" as *const u8 as *const libc::c_char,
                c,
                p,
                &mut *pfd.offset(p as isize),
            );
            p = p.wrapping_add(1);
            p;
        }
    }
    if (*c).sock != -(1 as libc::c_int) && (*c).rfd != (*c).sock {
        ev = 0 as libc::c_int as u_int;
        if (*c).io_want & 0x10 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint {
            ev |= 0x1 as libc::c_int as libc::c_uint;
        }
        if (*c).io_want & 0x20 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint {
            ev |= 0x4 as libc::c_int as libc::c_uint;
        }
        if ev != 0 as libc::c_int as libc::c_uint {
            (*c).pfds[3 as libc::c_int as usize] = p as libc::c_int;
            (*pfd.offset(p as isize)).fd = (*c).sock;
            (*pfd.offset(p as isize)).events = 0 as libc::c_int as libc::c_short;
            dump_channel_poll(
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"channel_prepare_pollfd\0",
                ))
                .as_ptr(),
                b"sock\0" as *const u8 as *const libc::c_char,
                c,
                p,
                &mut *pfd.offset(p as isize),
            );
            p = p.wrapping_add(1);
            p;
        }
    }
    *next_pollfd = p;
}
pub unsafe extern "C" fn channel_prepare_poll(
    mut ssh: *mut ssh,
    mut pfdp: *mut *mut pollfd,
    mut npfd_allocp: *mut u_int,
    mut npfd_activep: *mut u_int,
    mut npfd_reserved: u_int,
    mut timeout: *mut timespec,
) {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut i: u_int = 0;
    let mut oalloc: u_int = 0;
    let mut p: u_int = 0;
    let mut npfd: u_int = npfd_reserved;
    channel_before_prepare_io(ssh);
    i = 0 as libc::c_int as u_int;
    while i < (*sc).channels_alloc {
        if !(*((*sc).channels).offset(i as isize)).is_null() {
            let ref mut fresh33 = (**((*sc).channels).offset(i as isize)).io_ready;
            *fresh33 = 0 as libc::c_int as u_int;
            (**((*sc).channels).offset(i as isize)).io_want = *fresh33;
        }
        i = i.wrapping_add(1);
        i;
    }
    if (*sc).channels_alloc
        >= ((2147483647 as libc::c_int / 4 as libc::c_int) as libc::c_uint)
            .wrapping_sub(npfd_reserved)
    {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"channel_prepare_poll\0"))
                .as_ptr(),
            2756 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"too many channels\0" as *const u8 as *const libc::c_char,
        );
    }
    npfd = (npfd as libc::c_uint)
        .wrapping_add(((*sc).channels_alloc).wrapping_mul(4 as libc::c_int as libc::c_uint))
        as u_int as u_int;
    if npfd > *npfd_allocp {
        *pfdp = xrecallocarray(
            *pfdp as *mut libc::c_void,
            *npfd_allocp as size_t,
            npfd as size_t,
            ::core::mem::size_of::<pollfd>() as libc::c_ulong,
        ) as *mut pollfd;
        *npfd_allocp = npfd;
    }
    *npfd_activep = npfd_reserved;
    oalloc = (*sc).channels_alloc;
    channel_handler(ssh, CHAN_PRE as libc::c_int, timeout);
    if oalloc != (*sc).channels_alloc {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"channel_prepare_poll\0"))
                .as_ptr(),
            2771 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channels_alloc changed during CHAN_PRE (was %u, now %u)\0" as *const u8
                as *const libc::c_char,
            oalloc,
            (*sc).channels_alloc,
        );
    }
    p = npfd_reserved;
    i = 0 as libc::c_int as u_int;
    while i < (*sc).channels_alloc {
        channel_prepare_pollfd(*((*sc).channels).offset(i as isize), &mut p, *pfdp, npfd);
        i = i.wrapping_add(1);
        i;
    }
    *npfd_activep = p;
}
unsafe extern "C" fn fd_ready(
    mut c: *mut Channel,
    mut p: libc::c_int,
    mut pfds: *mut pollfd,
    mut npfd: u_int,
    mut fd: libc::c_int,
    mut what: *const libc::c_char,
    mut revents_mask: u_int,
    mut ready: u_int,
) {
    let mut pfd: *mut pollfd = &mut *pfds.offset(p as isize) as *mut pollfd;
    if fd == -(1 as libc::c_int) {
        return;
    }
    if p == -(1 as libc::c_int) || p as u_int >= npfd {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"fd_ready\0")).as_ptr(),
            2790 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d: bad pfd %d (max %u)\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            p,
            npfd,
        );
    }
    dump_channel_poll(
        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"fd_ready\0")).as_ptr(),
        what,
        c,
        p as u_int,
        pfd,
    );
    if (*pfd).fd != fd {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"fd_ready\0")).as_ptr(),
            2795 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d: inconsistent %s fd=%d pollfd[%u].fd %d r%d w%d e%d s%d\0" as *const u8
                as *const libc::c_char,
            (*c).self_0,
            what,
            fd,
            p,
            (*pfd).fd,
            (*c).rfd,
            (*c).wfd,
            (*c).efd,
            (*c).sock,
        );
    }
    if (*pfd).revents as libc::c_int & 0x20 as libc::c_int != 0 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"fd_ready\0")).as_ptr(),
            2799 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d: invalid %s pollfd[%u].fd %d r%d w%d e%d s%d\0" as *const u8
                as *const libc::c_char,
            (*c).self_0,
            what,
            p,
            (*pfd).fd,
            (*c).rfd,
            (*c).wfd,
            (*c).efd,
            (*c).sock,
        );
    }
    if (*pfd).revents as libc::c_uint
        & (revents_mask | 0x10 as libc::c_int as libc::c_uint | 0x8 as libc::c_int as libc::c_uint)
        != 0 as libc::c_int as libc::c_uint
    {
        (*c).io_ready |= ready & (*c).io_want;
    }
}
pub unsafe extern "C" fn channel_after_poll(
    mut ssh: *mut ssh,
    mut pfd: *mut pollfd,
    mut npfd: u_int,
) {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut i: u_int = 0;
    let mut p: libc::c_int = 0;
    let mut c: *mut Channel = 0 as *mut Channel;
    i = 0 as libc::c_int as u_int;
    while i < (*sc).channels_alloc {
        c = *((*sc).channels).offset(i as isize);
        if !c.is_null() {
            if (*c).rfd != -(1 as libc::c_int)
                && (*c).wfd != -(1 as libc::c_int)
                && (*c).rfd != (*c).wfd
                && ((*c).rfd == (*c).efd || (*c).rfd == (*c).sock)
            {
                sshfatal(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"channel_after_poll\0",
                    ))
                    .as_ptr(),
                    2836 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"channel %d: unexpected fds r%d w%d e%d s%d\0" as *const u8
                        as *const libc::c_char,
                    (*c).self_0,
                    (*c).rfd,
                    (*c).wfd,
                    (*c).efd,
                    (*c).sock,
                );
            }
            (*c).io_ready = 0 as libc::c_int as u_int;
            if (*c).rfd != -(1 as libc::c_int) && {
                p = (*c).pfds[0 as libc::c_int as usize];
                p != -(1 as libc::c_int)
            } {
                fd_ready(
                    c,
                    p,
                    pfd,
                    npfd,
                    (*c).rfd,
                    b"rfd\0" as *const u8 as *const libc::c_char,
                    0x1 as libc::c_int as u_int,
                    0x1 as libc::c_int as u_int,
                );
                if (*c).rfd == (*c).wfd {
                    fd_ready(
                        c,
                        p,
                        pfd,
                        npfd,
                        (*c).wfd,
                        b"wfd/r\0" as *const u8 as *const libc::c_char,
                        0x4 as libc::c_int as u_int,
                        0x2 as libc::c_int as u_int,
                    );
                }
                if (*c).rfd == (*c).efd {
                    fd_ready(
                        c,
                        p,
                        pfd,
                        npfd,
                        (*c).efd,
                        b"efdr/r\0" as *const u8 as *const libc::c_char,
                        0x1 as libc::c_int as u_int,
                        0x4 as libc::c_int as u_int,
                    );
                    fd_ready(
                        c,
                        p,
                        pfd,
                        npfd,
                        (*c).efd,
                        b"efdw/r\0" as *const u8 as *const libc::c_char,
                        0x4 as libc::c_int as u_int,
                        0x8 as libc::c_int as u_int,
                    );
                }
                if (*c).rfd == (*c).sock {
                    fd_ready(
                        c,
                        p,
                        pfd,
                        npfd,
                        (*c).sock,
                        b"sockr/r\0" as *const u8 as *const libc::c_char,
                        0x1 as libc::c_int as u_int,
                        0x10 as libc::c_int as u_int,
                    );
                    fd_ready(
                        c,
                        p,
                        pfd,
                        npfd,
                        (*c).sock,
                        b"sockw/r\0" as *const u8 as *const libc::c_char,
                        0x4 as libc::c_int as u_int,
                        0x20 as libc::c_int as u_int,
                    );
                }
                dump_channel_poll(
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"channel_after_poll\0",
                    ))
                    .as_ptr(),
                    b"rfd\0" as *const u8 as *const libc::c_char,
                    c,
                    p as u_int,
                    pfd,
                );
            }
            if (*c).wfd != -(1 as libc::c_int) && (*c).wfd != (*c).rfd && {
                p = (*c).pfds[1 as libc::c_int as usize];
                p != -(1 as libc::c_int)
            } {
                fd_ready(
                    c,
                    p,
                    pfd,
                    npfd,
                    (*c).wfd,
                    b"wfd\0" as *const u8 as *const libc::c_char,
                    0x4 as libc::c_int as u_int,
                    0x2 as libc::c_int as u_int,
                );
                dump_channel_poll(
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"channel_after_poll\0",
                    ))
                    .as_ptr(),
                    b"wfd\0" as *const u8 as *const libc::c_char,
                    c,
                    p as u_int,
                    pfd,
                );
            }
            if (*c).efd != -(1 as libc::c_int) && (*c).efd != (*c).rfd && {
                p = (*c).pfds[2 as libc::c_int as usize];
                p != -(1 as libc::c_int)
            } {
                fd_ready(
                    c,
                    p,
                    pfd,
                    npfd,
                    (*c).efd,
                    b"efdr\0" as *const u8 as *const libc::c_char,
                    0x1 as libc::c_int as u_int,
                    0x4 as libc::c_int as u_int,
                );
                fd_ready(
                    c,
                    p,
                    pfd,
                    npfd,
                    (*c).efd,
                    b"efdw\0" as *const u8 as *const libc::c_char,
                    0x4 as libc::c_int as u_int,
                    0x8 as libc::c_int as u_int,
                );
                dump_channel_poll(
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"channel_after_poll\0",
                    ))
                    .as_ptr(),
                    b"efd\0" as *const u8 as *const libc::c_char,
                    c,
                    p as u_int,
                    pfd,
                );
            }
            if (*c).sock != -(1 as libc::c_int) && (*c).sock != (*c).rfd && {
                p = (*c).pfds[3 as libc::c_int as usize];
                p != -(1 as libc::c_int)
            } {
                fd_ready(
                    c,
                    p,
                    pfd,
                    npfd,
                    (*c).sock,
                    b"sockr\0" as *const u8 as *const libc::c_char,
                    0x1 as libc::c_int as u_int,
                    0x10 as libc::c_int as u_int,
                );
                fd_ready(
                    c,
                    p,
                    pfd,
                    npfd,
                    (*c).sock,
                    b"sockw\0" as *const u8 as *const libc::c_char,
                    0x4 as libc::c_int as u_int,
                    0x20 as libc::c_int as u_int,
                );
                dump_channel_poll(
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"channel_after_poll\0",
                    ))
                    .as_ptr(),
                    b"sock\0" as *const u8 as *const libc::c_char,
                    c,
                    p as u_int,
                    pfd,
                );
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    channel_handler(ssh, CHAN_POST as libc::c_int, 0 as *mut timespec);
}
unsafe extern "C" fn channel_output_poll_input_open(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut len: size_t = 0;
    let mut plen: size_t = 0;
    let mut pkt: *const u_char = 0 as *const u_char;
    let mut r: libc::c_int = 0;
    len = sshbuf_len((*c).input);
    if len == 0 as libc::c_int as libc::c_ulong {
        if (*c).istate == 1 as libc::c_int as libc::c_uint {
            if (*c).extended_usage == 1 as libc::c_int
                && ((*c).efd != -(1 as libc::c_int)
                    || sshbuf_len((*c).extended) > 0 as libc::c_int as libc::c_ulong)
            {
                sshlog(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                        b"channel_output_poll_input_open\0",
                    ))
                    .as_ptr(),
                    2912 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"channel %d: ibuf_empty delayed efd %d/(%zu)\0" as *const u8
                        as *const libc::c_char,
                    (*c).self_0,
                    (*c).efd,
                    sshbuf_len((*c).extended),
                );
            } else {
                chan_ibuf_empty(ssh, c);
            }
        }
        return;
    }
    if (*c).have_remote_id == 0 {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                b"channel_output_poll_input_open\0",
            ))
            .as_ptr(),
            2920 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d: no remote id\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    if (*c).datagram != 0 {
        r = sshbuf_get_string_direct((*c).input, &mut pkt, &mut plen);
        if r != 0 as libc::c_int {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                    b"channel_output_poll_input_open\0",
                ))
                .as_ptr(),
                2925 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i: get datagram\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
        if plen > (*c).remote_window as libc::c_ulong
            || plen > (*c).remote_maxpacket as libc::c_ulong
        {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                    b"channel_output_poll_input_open\0",
                ))
                .as_ptr(),
                2932 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"channel %d: datagram too big\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
            return;
        }
        r = sshpkt_start(ssh, 94 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshpkt_put_u32(ssh, (*c).remote_id);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_put_string(ssh, pkt as *const libc::c_void, plen);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_send(ssh);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                    b"channel_output_poll_input_open\0",
                ))
                .as_ptr(),
                2940 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i: send datagram\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
        (*c).remote_window =
            ((*c).remote_window as libc::c_ulong).wrapping_sub(plen) as u_int as u_int;
        return;
    }
    if len > (*c).remote_window as libc::c_ulong {
        len = (*c).remote_window as size_t;
    }
    if len > (*c).remote_maxpacket as libc::c_ulong {
        len = (*c).remote_maxpacket as size_t;
    }
    if len == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    r = sshpkt_start(ssh, 94 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_u32(ssh, (*c).remote_id);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_string(ssh, sshbuf_ptr((*c).input) as *const libc::c_void, len);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                b"channel_output_poll_input_open\0",
            ))
            .as_ptr(),
            2956 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i: send data\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    r = sshbuf_consume((*c).input, len);
    if r != 0 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                b"channel_output_poll_input_open\0",
            ))
            .as_ptr(),
            2958 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i: consume\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    (*c).remote_window = ((*c).remote_window as libc::c_ulong).wrapping_sub(len) as u_int as u_int;
}
unsafe extern "C" fn channel_output_poll_extended_read(mut ssh: *mut ssh, mut c: *mut Channel) {
    let mut len: size_t = 0;
    let mut r: libc::c_int = 0;
    len = sshbuf_len((*c).extended);
    if len == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
            b"channel_output_poll_extended_read\0",
        ))
        .as_ptr(),
        2975 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: rwin %u elen %zu euse %d\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        (*c).remote_window,
        sshbuf_len((*c).extended),
        (*c).extended_usage,
    );
    if len > (*c).remote_window as libc::c_ulong {
        len = (*c).remote_window as size_t;
    }
    if len > (*c).remote_maxpacket as libc::c_ulong {
        len = (*c).remote_maxpacket as size_t;
    }
    if len == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    if (*c).have_remote_id == 0 {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                b"channel_output_poll_extended_read\0",
            ))
            .as_ptr(),
            2983 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d: no remote id\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    r = sshpkt_start(ssh, 95 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_u32(ssh, (*c).remote_id);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, 1 as libc::c_int as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_string(ssh, sshbuf_ptr((*c).extended) as *const libc::c_void, len);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                b"channel_output_poll_extended_read\0",
            ))
            .as_ptr(),
            2989 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i: data\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    r = sshbuf_consume((*c).extended, len);
    if r != 0 as libc::c_int {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                b"channel_output_poll_extended_read\0",
            ))
            .as_ptr(),
            2991 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i: consume\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    (*c).remote_window = ((*c).remote_window as libc::c_ulong).wrapping_sub(len) as u_int as u_int;
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
            b"channel_output_poll_extended_read\0",
        ))
        .as_ptr(),
        2993 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: sent ext data %zu\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        len,
    );
}
pub unsafe extern "C" fn channel_output_poll(mut ssh: *mut ssh) {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < (*sc).channels_alloc {
        c = *((*sc).channels).offset(i as isize);
        if !c.is_null() {
            if !((*c).type_0 != 4 as libc::c_int) {
                if (*c).flags & (0x1 as libc::c_int | 0x2 as libc::c_int) != 0 {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                            b"channel_output_poll\0",
                        ))
                        .as_ptr(),
                        3018 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG3,
                        0 as *const libc::c_char,
                        b"channel %d: will not send data after close\0" as *const u8
                            as *const libc::c_char,
                        (*c).self_0,
                    );
                } else {
                    if (*c).istate == 0 as libc::c_int as libc::c_uint
                        || (*c).istate == 1 as libc::c_int as libc::c_uint
                    {
                        channel_output_poll_input_open(ssh, c);
                    }
                    if (*c).flags & 0x4 as libc::c_int == 0
                        && (*c).extended_usage == 1 as libc::c_int
                    {
                        channel_output_poll_extended_read(ssh, c);
                    }
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
}
pub unsafe extern "C" fn channel_proxy_downstream(
    mut ssh: *mut ssh,
    mut downstream: *mut Channel,
) -> libc::c_int {
    let mut current_block: u64;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut original: *mut sshbuf = 0 as *mut sshbuf;
    let mut modified: *mut sshbuf = 0 as *mut sshbuf;
    let mut cp: *const u_char = 0 as *const u_char;
    let mut ctype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut listen_host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut type_0: u_char = 0;
    let mut have: size_t = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut r: libc::c_int = 0;
    let mut id: u_int = 0;
    let mut remote_id: u_int = 0;
    let mut listen_port: u_int = 0;
    r = sshbuf_get_string_direct((*downstream).input, &mut cp, &mut have);
    if r != 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"channel_proxy_downstream\0",
            ))
            .as_ptr(),
            3088 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if have < 2 as libc::c_int as libc::c_ulong {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"channel_proxy_downstream\0",
            ))
            .as_ptr(),
            3092 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"short message\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    type_0 = *cp.offset(1 as libc::c_int as isize);
    cp = cp.offset(2 as libc::c_int as isize);
    have =
        (have as libc::c_ulong).wrapping_sub(2 as libc::c_int as libc::c_ulong) as size_t as size_t;
    if ssh_packet_log_type(type_0) != 0 {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"channel_proxy_downstream\0",
            ))
            .as_ptr(),
            3101 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"channel %u: down->up: type %u\0" as *const u8 as *const libc::c_char,
            (*downstream).self_0,
            type_0 as libc::c_int,
        );
    }
    match type_0 as libc::c_int {
        90 => {
            original = sshbuf_from(cp as *const libc::c_void, have);
            if original.is_null() || {
                modified = sshbuf_new();
                modified.is_null()
            } {
                sshlog(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                        b"channel_proxy_downstream\0",
                    ))
                    .as_ptr(),
                    3107 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"alloc\0" as *const u8 as *const libc::c_char,
                );
                current_block = 11241368042544214213;
            } else {
                r = sshbuf_get_cstring(original, &mut ctype, 0 as *mut size_t);
                if r != 0 as libc::c_int || {
                    r = sshbuf_get_u32(original, &mut id);
                    r != 0 as libc::c_int
                } {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                            b"channel_proxy_downstream\0",
                        ))
                        .as_ptr(),
                        3112 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"parse\0" as *const u8 as *const libc::c_char,
                    );
                    current_block = 11241368042544214213;
                } else {
                    c = channel_new(
                        ssh,
                        b"mux-proxy\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                        20 as libc::c_int,
                        -(1 as libc::c_int),
                        -(1 as libc::c_int),
                        -(1 as libc::c_int),
                        0 as libc::c_int as u_int,
                        0 as libc::c_int as u_int,
                        0 as libc::c_int,
                        ctype,
                        1 as libc::c_int,
                    );
                    (*c).mux_ctx = downstream as *mut libc::c_void;
                    (*c).mux_downstream_id = id as libc::c_int;
                    r = sshbuf_put_cstring(modified, ctype);
                    if r != 0 as libc::c_int
                        || {
                            r = sshbuf_put_u32(modified, (*c).self_0 as u_int32_t);
                            r != 0 as libc::c_int
                        }
                        || {
                            r = sshbuf_putb(modified, original);
                            r != 0 as libc::c_int
                        }
                    {
                        sshlog(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"channel_proxy_downstream\0",
                            ))
                            .as_ptr(),
                            3122 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"compose\0" as *const u8 as *const libc::c_char,
                        );
                        channel_free(ssh, c);
                        current_block = 11241368042544214213;
                    } else {
                        current_block = 11793792312832361944;
                    }
                }
            }
        }
        91 => {
            original = sshbuf_from(cp as *const libc::c_void, have);
            if original.is_null() || {
                modified = sshbuf_new();
                modified.is_null()
            } {
                sshlog(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                        b"channel_proxy_downstream\0",
                    ))
                    .as_ptr(),
                    3134 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"alloc\0" as *const u8 as *const libc::c_char,
                );
                current_block = 11241368042544214213;
            } else {
                r = sshbuf_get_u32(original, &mut remote_id);
                if r != 0 as libc::c_int || {
                    r = sshbuf_get_u32(original, &mut id);
                    r != 0 as libc::c_int
                } {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                            b"channel_proxy_downstream\0",
                        ))
                        .as_ptr(),
                        3139 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"parse\0" as *const u8 as *const libc::c_char,
                    );
                    current_block = 11241368042544214213;
                } else {
                    c = channel_new(
                        ssh,
                        b"mux-proxy\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                        20 as libc::c_int,
                        -(1 as libc::c_int),
                        -(1 as libc::c_int),
                        -(1 as libc::c_int),
                        0 as libc::c_int as u_int,
                        0 as libc::c_int as u_int,
                        0 as libc::c_int,
                        b"mux-down-connect\0" as *const u8 as *const libc::c_char,
                        1 as libc::c_int,
                    );
                    (*c).mux_ctx = downstream as *mut libc::c_void;
                    (*c).mux_downstream_id = id as libc::c_int;
                    (*c).remote_id = remote_id;
                    (*c).have_remote_id = 1 as libc::c_int;
                    r = sshbuf_put_u32(modified, remote_id);
                    if r != 0 as libc::c_int
                        || {
                            r = sshbuf_put_u32(modified, (*c).self_0 as u_int32_t);
                            r != 0 as libc::c_int
                        }
                        || {
                            r = sshbuf_putb(modified, original);
                            r != 0 as libc::c_int
                        }
                    {
                        sshlog(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"channel_proxy_downstream\0",
                            ))
                            .as_ptr(),
                            3151 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"compose\0" as *const u8 as *const libc::c_char,
                        );
                        channel_free(ssh, c);
                        current_block = 11241368042544214213;
                    } else {
                        current_block = 11793792312832361944;
                    }
                }
            }
        }
        80 => {
            original = sshbuf_from(cp as *const libc::c_void, have);
            if original.is_null() {
                sshlog(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                        b"channel_proxy_downstream\0",
                    ))
                    .as_ptr(),
                    3158 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"alloc\0" as *const u8 as *const libc::c_char,
                );
                current_block = 11241368042544214213;
            } else {
                r = sshbuf_get_cstring(original, &mut ctype, 0 as *mut size_t);
                if r != 0 as libc::c_int {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                            b"channel_proxy_downstream\0",
                        ))
                        .as_ptr(),
                        3162 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"parse\0" as *const u8 as *const libc::c_char,
                    );
                    current_block = 11241368042544214213;
                } else if strcmp(
                    ctype,
                    b"tcpip-forward\0" as *const u8 as *const libc::c_char,
                ) != 0 as libc::c_int
                {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                            b"channel_proxy_downstream\0",
                        ))
                        .as_ptr(),
                        3166 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"unsupported request %s\0" as *const u8 as *const libc::c_char,
                        ctype,
                    );
                    current_block = 11241368042544214213;
                } else {
                    r = sshbuf_get_u8(original, 0 as *mut u_char);
                    if r != 0 as libc::c_int
                        || {
                            r = sshbuf_get_cstring(original, &mut listen_host, 0 as *mut size_t);
                            r != 0 as libc::c_int
                        }
                        || {
                            r = sshbuf_get_u32(original, &mut listen_port);
                            r != 0 as libc::c_int
                        }
                    {
                        sshlog(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"channel_proxy_downstream\0",
                            ))
                            .as_ptr(),
                            3172 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"parse\0" as *const u8 as *const libc::c_char,
                        );
                        current_block = 11241368042544214213;
                    } else if listen_port > 65535 as libc::c_int as libc::c_uint {
                        sshlog(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"channel_proxy_downstream\0",
                            ))
                            .as_ptr(),
                            3177 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"tcpip-forward for %s: bad port %u\0" as *const u8
                                as *const libc::c_char,
                            listen_host,
                            listen_port,
                        );
                        current_block = 11241368042544214213;
                    } else {
                        permission_set_add(
                            ssh,
                            0x101 as libc::c_int,
                            (1 as libc::c_int) << 1 as libc::c_int,
                            b"<mux>\0" as *const u8 as *const libc::c_char,
                            -(1 as libc::c_int),
                            listen_host,
                            0 as *const libc::c_char,
                            listen_port as libc::c_int,
                            downstream,
                        );
                        listen_host = 0 as *mut libc::c_char;
                        current_block = 11793792312832361944;
                    }
                }
            }
        }
        97 => {
            if have < 4 as libc::c_int as libc::c_ulong {
                current_block = 11793792312832361944;
            } else {
                remote_id = (*cp.offset(0 as libc::c_int as isize) as u_int32_t)
                    << 24 as libc::c_int
                    | (*cp.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
                    | (*cp.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
                    | *cp.offset(3 as libc::c_int as isize) as u_int32_t;
                c = channel_by_remote_id(ssh, remote_id);
                if !c.is_null() {
                    if (*c).flags & 0x2 as libc::c_int != 0 {
                        channel_free(ssh, c);
                    } else {
                        (*c).flags |= 0x1 as libc::c_int;
                    }
                }
                current_block = 11793792312832361944;
            }
        }
        _ => {
            current_block = 11793792312832361944;
        }
    }
    match current_block {
        11793792312832361944 => {
            if !modified.is_null() {
                r = sshpkt_start(ssh, type_0);
                if r != 0 as libc::c_int
                    || {
                        r = sshpkt_putb(ssh, modified);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshpkt_send(ssh);
                        r != 0 as libc::c_int
                    }
                {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                            b"channel_proxy_downstream\0",
                        ))
                        .as_ptr(),
                        3201 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"send\0" as *const u8 as *const libc::c_char,
                    );
                    current_block = 11241368042544214213;
                } else {
                    current_block = 13325891313334703151;
                }
            } else {
                r = sshpkt_start(ssh, type_0);
                if r != 0 as libc::c_int
                    || {
                        r = sshpkt_put(ssh, cp as *const libc::c_void, have);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshpkt_send(ssh);
                        r != 0 as libc::c_int
                    }
                {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                            b"channel_proxy_downstream\0",
                        ))
                        .as_ptr(),
                        3208 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"send\0" as *const u8 as *const libc::c_char,
                    );
                    current_block = 11241368042544214213;
                } else {
                    current_block = 13325891313334703151;
                }
            }
            match current_block {
                11241368042544214213 => {}
                _ => {
                    ret = 0 as libc::c_int;
                }
            }
        }
        _ => {}
    }
    free(ctype as *mut libc::c_void);
    free(listen_host as *mut libc::c_void);
    sshbuf_free(original);
    sshbuf_free(modified);
    return ret;
}
pub unsafe extern "C" fn channel_proxy_upstream(
    mut c: *mut Channel,
    mut type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut b: *mut sshbuf = 0 as *mut sshbuf;
    let mut downstream: *mut Channel = 0 as *mut Channel;
    let mut cp: *const u_char = 0 as *const u_char;
    let mut len: size_t = 0;
    let mut r: libc::c_int = 0;
    if c.is_null() || (*c).type_0 != 20 as libc::c_int {
        return 0 as libc::c_int;
    }
    downstream = (*c).mux_ctx as *mut Channel;
    if downstream.is_null() {
        return 0 as libc::c_int;
    }
    match type_0 {
        97 | 94 | 96 | 95 | 91 | 92 | 93 | 99 | 100 | 98 => {}
        _ => {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"channel_proxy_upstream\0",
                ))
                .as_ptr(),
                3259 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"channel %u: unsupported type %u\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
                type_0,
            );
            return 0 as libc::c_int;
        }
    }
    b = sshbuf_new();
    if b.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"channel_proxy_upstream\0",
            ))
            .as_ptr(),
            3263 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"alloc reply\0" as *const u8 as *const libc::c_char,
        );
    } else {
        cp = sshpkt_ptr(ssh, &mut len);
        if cp.is_null() {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                    b"channel_proxy_upstream\0",
                ))
                .as_ptr(),
                3269 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"no packet\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = sshbuf_put_u8(b, 0 as libc::c_int as u_char);
            if r != 0 as libc::c_int
                || {
                    r = sshbuf_put_u8(b, type_0 as u_char);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_u32(b, (*c).mux_downstream_id as u_int32_t);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put(b, cp as *const libc::c_void, len);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_stringb((*downstream).output, b);
                    r != 0 as libc::c_int
                }
            {
                sshlog(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"channel_proxy_upstream\0",
                    ))
                    .as_ptr(),
                    3278 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"compose muxclient\0" as *const u8 as *const libc::c_char,
                );
            } else if ssh_packet_log_type(type_0 as u_char) != 0 {
                sshlog(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                        b"channel_proxy_upstream\0",
                    ))
                    .as_ptr(),
                    3283 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"channel %u: up->down: type %u\0" as *const u8 as *const libc::c_char,
                    (*c).self_0,
                    type_0,
                );
            }
        }
    }
    match type_0 {
        91 => {
            if !cp.is_null() && len > 4 as libc::c_int as libc::c_ulong {
                (*c).remote_id = (*cp.offset(0 as libc::c_int as isize) as u_int32_t)
                    << 24 as libc::c_int
                    | (*cp.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
                    | (*cp.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
                    | *cp.offset(3 as libc::c_int as isize) as u_int32_t;
                (*c).have_remote_id = 1 as libc::c_int;
            }
        }
        97 => {
            if (*c).flags & 0x1 as libc::c_int != 0 {
                channel_free(ssh, c);
            } else {
                (*c).flags |= 0x2 as libc::c_int;
            }
        }
        _ => {}
    }
    sshbuf_free(b);
    return 1 as libc::c_int;
}
unsafe extern "C" fn channel_parse_id(
    mut ssh: *mut ssh,
    mut where_0: *const libc::c_char,
    mut what: *const libc::c_char,
) -> libc::c_int {
    let mut id: u_int32_t = 0;
    let mut r: libc::c_int = 0;
    r = sshpkt_get_u32(ssh, &mut id);
    if r != 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"channel_parse_id\0"))
                .as_ptr(),
            3315 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"%s: parse id\0" as *const u8 as *const libc::c_char,
            where_0,
        );
        ssh_packet_disconnect(
            ssh,
            b"Invalid %s message\0" as *const u8 as *const libc::c_char,
            what,
        );
    }
    if id > 2147483647 as libc::c_int as libc::c_uint {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"channel_parse_id\0"))
                .as_ptr(),
            3319 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"%s: bad channel id %u\0" as *const u8 as *const libc::c_char,
            where_0,
            id,
        );
        ssh_packet_disconnect(
            ssh,
            b"Invalid %s channel id\0" as *const u8 as *const libc::c_char,
            what,
        );
    }
    return id as libc::c_int;
}
unsafe extern "C" fn channel_from_packet_id(
    mut ssh: *mut ssh,
    mut where_0: *const libc::c_char,
    mut what: *const libc::c_char,
) -> *mut Channel {
    let mut id: libc::c_int = channel_parse_id(ssh, where_0, what);
    let mut c: *mut Channel = 0 as *mut Channel;
    c = channel_lookup(ssh, id);
    if c.is_null() {
        ssh_packet_disconnect(
            ssh,
            b"%s packet referred to nonexistent channel %d\0" as *const u8 as *const libc::c_char,
            what,
            id,
        );
    }
    return c;
}
pub unsafe extern "C" fn channel_input_data(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut data: *const u_char = 0 as *const u_char;
    let mut data_len: size_t = 0;
    let mut win_len: size_t = 0;
    let mut c: *mut Channel = channel_from_packet_id(
        ssh,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"channel_input_data\0"))
            .as_ptr(),
        b"data\0" as *const u8 as *const libc::c_char,
    );
    let mut r: libc::c_int = 0;
    if channel_proxy_upstream(c, type_0, seq, ssh) != 0 {
        return 0 as libc::c_int;
    }
    if (*c).type_0 != 4 as libc::c_int
        && (*c).type_0 != 21 as libc::c_int
        && (*c).type_0 != 22 as libc::c_int
        && (*c).type_0 != 7 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    r = sshpkt_get_string_direct(ssh, &mut data, &mut data_len);
    if r != 0 as libc::c_int || {
        r = sshpkt_get_end(ssh);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"channel_input_data\0"))
                .as_ptr(),
            3360 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i: get data\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    win_len = data_len;
    if (*c).datagram != 0 {
        win_len = (win_len as libc::c_ulong).wrapping_add(4 as libc::c_int as libc::c_ulong)
            as size_t as size_t;
    }
    if (*c).ostate != 0 as libc::c_int as libc::c_uint {
        (*c).local_window =
            ((*c).local_window as libc::c_ulong).wrapping_sub(win_len) as u_int as u_int;
        (*c).local_consumed =
            ((*c).local_consumed as libc::c_ulong).wrapping_add(win_len) as u_int as u_int;
        return 0 as libc::c_int;
    }
    if win_len > (*c).local_maxpacket as libc::c_ulong {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"channel_input_data\0"))
                .as_ptr(),
            3379 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"channel %d: rcvd big packet %zu, maxpack %u\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            win_len,
            (*c).local_maxpacket,
        );
        return 0 as libc::c_int;
    }
    if win_len > (*c).local_window as libc::c_ulong {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"channel_input_data\0"))
                .as_ptr(),
            3384 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"channel %d: rcvd too much data %zu, win %u\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            win_len,
            (*c).local_window,
        );
        return 0 as libc::c_int;
    }
    (*c).local_window =
        ((*c).local_window as libc::c_ulong).wrapping_sub(win_len) as u_int as u_int;
    if (*c).datagram != 0 {
        r = sshbuf_put_string((*c).output, data as *const libc::c_void, data_len);
        if r != 0 as libc::c_int {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"channel_input_data\0",
                ))
                .as_ptr(),
                3391 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i: append datagram\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
    } else {
        r = sshbuf_put((*c).output, data as *const libc::c_void, data_len);
        if r != 0 as libc::c_int {
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"channel_input_data\0",
                ))
                .as_ptr(),
                3393 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"channel %i: append data\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn channel_input_extended_data(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut data: *const u_char = 0 as *const u_char;
    let mut data_len: size_t = 0;
    let mut tcode: u_int32_t = 0;
    let mut c: *mut Channel = channel_from_packet_id(
        ssh,
        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
            b"channel_input_extended_data\0",
        ))
        .as_ptr(),
        b"extended data\0" as *const u8 as *const libc::c_char,
    );
    let mut r: libc::c_int = 0;
    if channel_proxy_upstream(c, type_0, seq, ssh) != 0 {
        return 0 as libc::c_int;
    }
    if (*c).type_0 != 4 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"channel_input_extended_data\0",
            ))
            .as_ptr(),
            3410 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"channel %d: ext data for non open\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        return 0 as libc::c_int;
    }
    if (*c).flags & 0x8 as libc::c_int != 0 {
        if (*ssh).compat & 0x200000 as libc::c_int != 0 {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                    b"channel_input_extended_data\0",
                ))
                .as_ptr(),
                3416 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"channel %d: accepting ext data after eof\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
            );
        } else {
            ssh_packet_disconnect(
                ssh,
                b"Received extended_data after EOF on channel %d.\0" as *const u8
                    as *const libc::c_char,
                (*c).self_0,
            );
        }
    }
    r = sshpkt_get_u32(ssh, &mut tcode);
    if r != 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"channel_input_extended_data\0",
            ))
            .as_ptr(),
            3423 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse tcode\0" as *const u8 as *const libc::c_char,
        );
        ssh_packet_disconnect(
            ssh,
            b"Invalid extended_data message\0" as *const u8 as *const libc::c_char,
        );
    }
    if (*c).efd == -(1 as libc::c_int)
        || (*c).extended_usage != 2 as libc::c_int
        || tcode != 1 as libc::c_int as libc::c_uint
    {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"channel_input_extended_data\0",
            ))
            .as_ptr(),
            3429 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"channel %d: bad ext data\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        return 0 as libc::c_int;
    }
    r = sshpkt_get_string_direct(ssh, &mut data, &mut data_len);
    if r != 0 as libc::c_int || {
        r = sshpkt_get_end(ssh);
        r != 0 as libc::c_int
    } {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"channel_input_extended_data\0",
            ))
            .as_ptr(),
            3434 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse data\0" as *const u8 as *const libc::c_char,
        );
        ssh_packet_disconnect(
            ssh,
            b"Invalid extended_data message\0" as *const u8 as *const libc::c_char,
        );
    }
    if data_len > (*c).local_window as libc::c_ulong {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"channel_input_extended_data\0",
            ))
            .as_ptr(),
            3440 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"channel %d: rcvd too much extended_data %zu, win %u\0" as *const u8
                as *const libc::c_char,
            (*c).self_0,
            data_len,
            (*c).local_window,
        );
        return 0 as libc::c_int;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
            b"channel_input_extended_data\0",
        ))
        .as_ptr(),
        3443 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: rcvd ext data %zu\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        data_len,
    );
    r = sshbuf_put((*c).extended, data as *const libc::c_void, data_len);
    if r != 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"channel_input_extended_data\0",
            ))
            .as_ptr(),
            3446 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"append\0" as *const u8 as *const libc::c_char,
        );
    }
    (*c).local_window =
        ((*c).local_window as libc::c_ulong).wrapping_sub(data_len) as u_int as u_int;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn channel_input_ieof(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut c: *mut Channel = channel_from_packet_id(
        ssh,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"channel_input_ieof\0"))
            .as_ptr(),
        b"ieof\0" as *const u8 as *const libc::c_char,
    );
    let mut r: libc::c_int = 0;
    r = sshpkt_get_end(ssh);
    if r != 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"channel_input_ieof\0"))
                .as_ptr(),
            3458 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse data\0" as *const u8 as *const libc::c_char,
        );
        ssh_packet_disconnect(
            ssh,
            b"Invalid ieof message\0" as *const u8 as *const libc::c_char,
        );
    }
    if channel_proxy_upstream(c, type_0, seq, ssh) != 0 {
        return 0 as libc::c_int;
    }
    chan_rcvd_ieof(ssh, c);
    if (*c).force_drain != 0 && (*c).istate == 0 as libc::c_int as libc::c_uint {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"channel_input_ieof\0"))
                .as_ptr(),
            3468 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"channel %d: FORCE input drain\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        (*c).istate = 1 as libc::c_int as u_int;
        if sshbuf_len((*c).input) == 0 as libc::c_int as libc::c_ulong {
            chan_ibuf_empty(ssh, c);
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn channel_input_oclose(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut c: *mut Channel = channel_from_packet_id(
        ssh,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"channel_input_oclose\0"))
            .as_ptr(),
        b"oclose\0" as *const u8 as *const libc::c_char,
    );
    let mut r: libc::c_int = 0;
    if channel_proxy_upstream(c, type_0, seq, ssh) != 0 {
        return 0 as libc::c_int;
    }
    r = sshpkt_get_end(ssh);
    if r != 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"channel_input_oclose\0"))
                .as_ptr(),
            3485 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse data\0" as *const u8 as *const libc::c_char,
        );
        ssh_packet_disconnect(
            ssh,
            b"Invalid oclose message\0" as *const u8 as *const libc::c_char,
        );
    }
    chan_rcvd_oclose(ssh, c);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn channel_input_open_confirmation(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut c: *mut Channel = channel_from_packet_id(
        ssh,
        (*::core::mem::transmute::<&[u8; 32], &[libc::c_char; 32]>(
            b"channel_input_open_confirmation\0",
        ))
        .as_ptr(),
        b"open confirmation\0" as *const u8 as *const libc::c_char,
    );
    let mut remote_window: u_int32_t = 0;
    let mut remote_maxpacket: u_int32_t = 0;
    let mut r: libc::c_int = 0;
    if channel_proxy_upstream(c, type_0, seq, ssh) != 0 {
        return 0 as libc::c_int;
    }
    if (*c).type_0 != 3 as libc::c_int {
        ssh_packet_disconnect(
            ssh,
            b"Received open confirmation for non-opening channel %d.\0" as *const u8
                as *const libc::c_char,
            (*c).self_0,
        );
    }
    r = sshpkt_get_u32(ssh, &mut (*c).remote_id);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_get_u32(ssh, &mut remote_window);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_u32(ssh, &mut remote_maxpacket);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }
    {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 32], &[libc::c_char; 32]>(
                b"channel_input_open_confirmation\0",
            ))
            .as_ptr(),
            3512 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"window/maxpacket\0" as *const u8 as *const libc::c_char,
        );
        ssh_packet_disconnect(
            ssh,
            b"Invalid open confirmation message\0" as *const u8 as *const libc::c_char,
        );
    }
    (*c).have_remote_id = 1 as libc::c_int;
    (*c).remote_window = remote_window;
    (*c).remote_maxpacket = remote_maxpacket;
    (*c).type_0 = 4 as libc::c_int;
    if ((*c).open_confirm).is_some() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 32], &[libc::c_char; 32]>(
                b"channel_input_open_confirmation\0",
            ))
            .as_ptr(),
            3521 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: callback start\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        ((*c).open_confirm).expect("non-null function pointer")(
            ssh,
            (*c).self_0,
            1 as libc::c_int,
            (*c).open_confirm_ctx,
        );
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 32], &[libc::c_char; 32]>(
                b"channel_input_open_confirmation\0",
            ))
            .as_ptr(),
            3523 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: callback done\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    (*c).lastused = monotime();
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 32], &[libc::c_char; 32]>(
            b"channel_input_open_confirmation\0",
        ))
        .as_ptr(),
        3527 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: open confirm rwindow %u rmax %u\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        (*c).remote_window,
        (*c).remote_maxpacket,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn reason2txt(mut reason: libc::c_int) -> *mut libc::c_char {
    match reason {
        1 => {
            return b"administratively prohibited\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
        }
        2 => {
            return b"connect failed\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
        3 => {
            return b"unknown channel type\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char;
        }
        4 => {
            return b"resource shortage\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        }
        _ => {}
    }
    return b"unknown reason\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
}
pub unsafe extern "C" fn channel_input_open_failure(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut c: *mut Channel = channel_from_packet_id(
        ssh,
        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
            b"channel_input_open_failure\0",
        ))
        .as_ptr(),
        b"open failure\0" as *const u8 as *const libc::c_char,
    );
    let mut reason: u_int32_t = 0;
    let mut msg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    if channel_proxy_upstream(c, type_0, seq, ssh) != 0 {
        return 0 as libc::c_int;
    }
    if (*c).type_0 != 3 as libc::c_int {
        ssh_packet_disconnect(
            ssh,
            b"Received open failure for non-opening channel %d.\0" as *const u8
                as *const libc::c_char,
            (*c).self_0,
        );
    }
    r = sshpkt_get_u32(ssh, &mut reason);
    if r != 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"channel_input_open_failure\0",
            ))
            .as_ptr(),
            3561 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse reason\0" as *const u8 as *const libc::c_char,
        );
        ssh_packet_disconnect(
            ssh,
            b"Invalid open failure message\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshpkt_get_cstring(ssh, &mut msg, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_get_string_direct(ssh, 0 as *mut *const u_char, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }
    {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"channel_input_open_failure\0",
            ))
            .as_ptr(),
            3568 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse msg/lang\0" as *const u8 as *const libc::c_char,
        );
        ssh_packet_disconnect(
            ssh,
            b"Invalid open failure message\0" as *const u8 as *const libc::c_char,
        );
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
            b"channel_input_open_failure\0",
        ))
        .as_ptr(),
        3572 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"channel %d: open failed: %s%s%s\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        reason2txt(reason as libc::c_int),
        if !msg.is_null() {
            b": \0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !msg.is_null() {
            msg as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
    );
    free(msg as *mut libc::c_void);
    if ((*c).open_confirm).is_some() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"channel_input_open_failure\0",
            ))
            .as_ptr(),
            3575 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: callback start\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
        ((*c).open_confirm).expect("non-null function pointer")(
            ssh,
            (*c).self_0,
            0 as libc::c_int,
            (*c).open_confirm_ctx,
        );
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"channel_input_open_failure\0",
            ))
            .as_ptr(),
            3577 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"channel %d: callback done\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    chan_mark_dead(ssh, c);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn channel_input_window_adjust(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut id: libc::c_int = channel_parse_id(
        ssh,
        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
            b"channel_input_window_adjust\0",
        ))
        .as_ptr(),
        b"window adjust\0" as *const u8 as *const libc::c_char,
    );
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut adjust: u_int32_t = 0;
    let mut new_rwin: u_int = 0;
    let mut r: libc::c_int = 0;
    c = channel_lookup(ssh, id);
    if c.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"channel_input_window_adjust\0",
            ))
            .as_ptr(),
            3594 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Received window adjust for non-open channel %d.\0" as *const u8
                as *const libc::c_char,
            id,
        );
        return 0 as libc::c_int;
    }
    if channel_proxy_upstream(c, type_0, seq, ssh) != 0 {
        return 0 as libc::c_int;
    }
    r = sshpkt_get_u32(ssh, &mut adjust);
    if r != 0 as libc::c_int || {
        r = sshpkt_get_end(ssh);
        r != 0 as libc::c_int
    } {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"channel_input_window_adjust\0",
            ))
            .as_ptr(),
            3602 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse adjust\0" as *const u8 as *const libc::c_char,
        );
        ssh_packet_disconnect(
            ssh,
            b"Invalid window adjust message\0" as *const u8 as *const libc::c_char,
        );
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
            b"channel_input_window_adjust\0",
        ))
        .as_ptr(),
        3605 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"channel %d: rcvd adjust %u\0" as *const u8 as *const libc::c_char,
        (*c).self_0,
        adjust,
    );
    new_rwin = ((*c).remote_window).wrapping_add(adjust);
    if new_rwin < (*c).remote_window {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"channel_input_window_adjust\0",
            ))
            .as_ptr(),
            3608 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d: adjust %u overflows remote window %u\0" as *const u8
                as *const libc::c_char,
            (*c).self_0,
            adjust,
            (*c).remote_window,
        );
    }
    (*c).remote_window = new_rwin;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn channel_input_status_confirm(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut id: libc::c_int = channel_parse_id(
        ssh,
        (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
            b"channel_input_status_confirm\0",
        ))
        .as_ptr(),
        b"status confirm\0" as *const u8 as *const libc::c_char,
    );
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut cc: *mut channel_confirm = 0 as *mut channel_confirm;
    ssh_packet_set_alive_timeouts(ssh, 0 as libc::c_int);
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
            b"channel_input_status_confirm\0",
        ))
        .as_ptr(),
        3624 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"type %d id %d\0" as *const u8 as *const libc::c_char,
        type_0,
        id,
    );
    c = channel_lookup(ssh, id);
    if c.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"channel_input_status_confirm\0",
            ))
            .as_ptr(),
            3627 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"%d: unknown\0" as *const u8 as *const libc::c_char,
            id,
        );
        return 0 as libc::c_int;
    }
    if channel_proxy_upstream(c, type_0, seq, ssh) != 0 {
        return 0 as libc::c_int;
    }
    if sshpkt_get_end(ssh) != 0 as libc::c_int {
        ssh_packet_disconnect(
            ssh,
            b"Invalid status confirm message\0" as *const u8 as *const libc::c_char,
        );
    }
    cc = (*c).status_confirms.tqh_first;
    if cc.is_null() {
        return 0 as libc::c_int;
    }
    ((*cc).cb).expect("non-null function pointer")(ssh, type_0, c, (*cc).ctx);
    if !((*cc).entry.tqe_next).is_null() {
        (*(*cc).entry.tqe_next).entry.tqe_prev = (*cc).entry.tqe_prev;
    } else {
        (*c).status_confirms.tqh_last = (*cc).entry.tqe_prev;
    }
    *(*cc).entry.tqe_prev = (*cc).entry.tqe_next;
    freezero(
        cc as *mut libc::c_void,
        ::core::mem::size_of::<channel_confirm>() as libc::c_ulong,
    );
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn channel_set_af(mut ssh: *mut ssh, mut af: libc::c_int) {
    (*(*ssh).chanctxt).IPv4or6 = af;
}
unsafe extern "C" fn channel_fwd_bind_addr(
    mut ssh: *mut ssh,
    mut listen_addr: *const libc::c_char,
    mut wildcardp: *mut libc::c_int,
    mut is_client: libc::c_int,
    mut fwd_opts: *mut ForwardOptions,
) -> *const libc::c_char {
    let mut addr: *const libc::c_char = 0 as *const libc::c_char;
    let mut wildcard: libc::c_int = 0 as libc::c_int;
    if listen_addr.is_null() {
        if (*fwd_opts).gateway_ports != 0 {
            wildcard = 1 as libc::c_int;
        }
    } else if (*fwd_opts).gateway_ports != 0 || is_client != 0 {
        if (*ssh).compat & 0x1000000 as libc::c_int != 0
            && strcmp(
                listen_addr,
                b"0.0.0.0\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
            && is_client == 0 as libc::c_int
            || *listen_addr as libc::c_int == '\0' as i32
            || strcmp(listen_addr, b"*\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            || is_client == 0 && (*fwd_opts).gateway_ports == 1 as libc::c_int
        {
            wildcard = 1 as libc::c_int;
            if *listen_addr as libc::c_int != '\0' as i32
                && strcmp(
                    listen_addr,
                    b"0.0.0.0\0" as *const u8 as *const libc::c_char,
                ) != 0 as libc::c_int
                && strcmp(listen_addr, b"*\0" as *const u8 as *const libc::c_char)
                    != 0 as libc::c_int
            {
                ssh_packet_send_debug(
                    ssh,
                    b"Forwarding listen address \"%s\" overridden by server GatewayPorts\0"
                        as *const u8 as *const libc::c_char,
                    listen_addr,
                );
            }
        } else if strcmp(
            listen_addr,
            b"localhost\0" as *const u8 as *const libc::c_char,
        ) != 0 as libc::c_int
            || strcmp(
                listen_addr,
                b"127.0.0.1\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
            || strcmp(listen_addr, b"::1\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            addr = listen_addr;
        }
    } else if strcmp(
        listen_addr,
        b"127.0.0.1\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
        || strcmp(listen_addr, b"::1\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        addr = listen_addr;
    }
    if !wildcardp.is_null() {
        *wildcardp = wildcard;
    }
    return addr;
}
unsafe extern "C" fn channel_setup_fwd_listener_tcpip(
    mut ssh: *mut ssh,
    mut type_0: libc::c_int,
    mut fwd: *mut Forward,
    mut allocated_listen_port: *mut libc::c_int,
    mut fwd_opts: *mut ForwardOptions,
) -> libc::c_int {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut sock: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut wildcard: libc::c_int = 0 as libc::c_int;
    let mut is_client: libc::c_int = 0;
    let mut hints: addrinfo = addrinfo {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: 0 as *mut sockaddr,
        ai_canonname: 0 as *mut libc::c_char,
        ai_next: 0 as *mut addrinfo,
    };
    let mut ai: *mut addrinfo = 0 as *mut addrinfo;
    let mut aitop: *mut addrinfo = 0 as *mut addrinfo;
    let mut host: *const libc::c_char = 0 as *const libc::c_char;
    let mut addr: *const libc::c_char = 0 as *const libc::c_char;
    let mut ntop: [libc::c_char; 1025] = [0; 1025];
    let mut strport: [libc::c_char; 32] = [0; 32];
    let mut lport_p: *mut in_port_t = 0 as *mut in_port_t;
    is_client = (type_0 == 2 as libc::c_int) as libc::c_int;
    if is_client != 0 && !((*fwd).connect_path).is_null() {
        host = (*fwd).connect_path;
    } else {
        host = if type_0 == 11 as libc::c_int {
            (*fwd).listen_host
        } else {
            (*fwd).connect_host
        };
        if host.is_null() {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                    b"channel_setup_fwd_listener_tcpip\0",
                ))
                .as_ptr(),
                3740 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"No forward host name.\0" as *const u8 as *const libc::c_char,
            );
            return 0 as libc::c_int;
        }
        if strlen(host) >= 1025 as libc::c_int as libc::c_ulong {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                    b"channel_setup_fwd_listener_tcpip\0",
                ))
                .as_ptr(),
                3744 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Forward host name too long.\0" as *const u8 as *const libc::c_char,
            );
            return 0 as libc::c_int;
        }
    }
    addr = channel_fwd_bind_addr(ssh, (*fwd).listen_host, &mut wildcard, is_client, fwd_opts);
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
            b"channel_setup_fwd_listener_tcpip\0",
        ))
        .as_ptr(),
        3753 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"type %d wildcard %d addr %s\0" as *const u8 as *const libc::c_char,
        type_0,
        wildcard,
        if addr.is_null() {
            b"NULL\0" as *const u8 as *const libc::c_char
        } else {
            addr
        },
    );
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_family = (*(*ssh).chanctxt).IPv4or6;
    hints.ai_flags = if wildcard != 0 {
        0x1 as libc::c_int
    } else {
        0 as libc::c_int
    };
    hints.ai_socktype = SOCK_STREAM as libc::c_int;
    snprintf(
        strport.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
        b"%d\0" as *const u8 as *const libc::c_char,
        (*fwd).listen_port,
    );
    r = getaddrinfo(addr, strport.as_mut_ptr(), &mut hints, &mut aitop);
    if r != 0 as libc::c_int {
        if addr.is_null() {
            ssh_packet_disconnect(
                ssh,
                b"getaddrinfo: fatal error: %s\0" as *const u8 as *const libc::c_char,
                ssh_gai_strerror(r),
            );
        } else {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                    b"channel_setup_fwd_listener_tcpip\0",
                ))
                .as_ptr(),
                3771 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"getaddrinfo(%.64s): %s\0" as *const u8 as *const libc::c_char,
                addr,
                ssh_gai_strerror(r),
            );
        }
        return 0 as libc::c_int;
    }
    if !allocated_listen_port.is_null() {
        *allocated_listen_port = 0 as libc::c_int;
    }
    let mut current_block_60: u64;
    ai = aitop;
    while !ai.is_null() {
        match (*ai).ai_family {
            2 => {
                lport_p = &mut (*((*ai).ai_addr as *mut sockaddr_in)).sin_port;
                current_block_60 = 4488286894823169796;
            }
            10 => {
                lport_p = &mut (*((*ai).ai_addr as *mut sockaddr_in6)).sin6_port;
                current_block_60 = 4488286894823169796;
            }
            _ => {
                current_block_60 = 10043043949733653460;
            }
        }
        match current_block_60 {
            4488286894823169796 => {
                if type_0 == 11 as libc::c_int
                    && (*fwd).listen_port == 0 as libc::c_int
                    && !allocated_listen_port.is_null()
                    && *allocated_listen_port > 0 as libc::c_int
                {
                    *lport_p = __bswap_16(*allocated_listen_port as __uint16_t);
                }
                if getnameinfo(
                    (*ai).ai_addr,
                    (*ai).ai_addrlen,
                    ntop.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as socklen_t,
                    strport.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong as socklen_t,
                    1 as libc::c_int | 2 as libc::c_int,
                ) != 0 as libc::c_int
                {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                            b"channel_setup_fwd_listener_tcpip\0",
                        ))
                        .as_ptr(),
                        3802 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"getnameinfo failed\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    sock = socket((*ai).ai_family, (*ai).ai_socktype, (*ai).ai_protocol);
                    if sock == -(1 as libc::c_int) {
                        sshlog(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                                b"channel_setup_fwd_listener_tcpip\0",
                            ))
                            .as_ptr(),
                            3810 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_VERBOSE,
                            0 as *const libc::c_char,
                            b"socket [%s]:%s: %.100s\0" as *const u8 as *const libc::c_char,
                            ntop.as_mut_ptr(),
                            strport.as_mut_ptr(),
                            strerror(*__errno_location()),
                        );
                    } else {
                        set_reuseaddr(sock);
                        if (*ai).ai_family == 10 as libc::c_int {
                            sock_set_v6only(sock);
                        }
                        sshlog(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                                b"channel_setup_fwd_listener_tcpip\0",
                            ))
                            .as_ptr(),
                            3819 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"Local forwarding listening on %s port %s.\0" as *const u8
                                as *const libc::c_char,
                            ntop.as_mut_ptr(),
                            strport.as_mut_ptr(),
                        );
                        if bind(
                            sock,
                            __CONST_SOCKADDR_ARG {
                                __sockaddr__: (*ai).ai_addr,
                            },
                            (*ai).ai_addrlen,
                        ) == -(1 as libc::c_int)
                        {
                            if ((*ai).ai_next).is_null() {
                                sshlog(
                                    b"channels.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                                        b"channel_setup_fwd_listener_tcpip\0",
                                    ))
                                    .as_ptr(),
                                    3829 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"bind [%s]:%s: %.100s\0" as *const u8 as *const libc::c_char,
                                    ntop.as_mut_ptr(),
                                    strport.as_mut_ptr(),
                                    strerror(*__errno_location()),
                                );
                            } else {
                                sshlog(
                                    b"channels.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                                        b"channel_setup_fwd_listener_tcpip\0",
                                    ))
                                    .as_ptr(),
                                    3832 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_VERBOSE,
                                    0 as *const libc::c_char,
                                    b"bind [%s]:%s: %.100s\0" as *const u8 as *const libc::c_char,
                                    ntop.as_mut_ptr(),
                                    strport.as_mut_ptr(),
                                    strerror(*__errno_location()),
                                );
                            }
                            close(sock);
                        } else if listen(sock, 128 as libc::c_int) == -(1 as libc::c_int) {
                            sshlog(
                                b"channels.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                                    b"channel_setup_fwd_listener_tcpip\0",
                                ))
                                .as_ptr(),
                                3840 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"listen [%s]:%s: %.100s\0" as *const u8 as *const libc::c_char,
                                ntop.as_mut_ptr(),
                                strport.as_mut_ptr(),
                                strerror(*__errno_location()),
                            );
                            close(sock);
                        } else {
                            if type_0 == 11 as libc::c_int
                                && (*fwd).listen_port == 0 as libc::c_int
                                && !allocated_listen_port.is_null()
                                && *allocated_listen_port == 0 as libc::c_int
                            {
                                *allocated_listen_port = get_local_port(sock);
                                sshlog(
                                    b"channels.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                                        b"channel_setup_fwd_listener_tcpip\0",
                                    ))
                                    .as_ptr(),
                                    3855 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG1,
                                    0 as *const libc::c_char,
                                    b"Allocated listen port %d\0" as *const u8
                                        as *const libc::c_char,
                                    *allocated_listen_port,
                                );
                            }
                            c = channel_new(
                                ssh,
                                b"port-listener\0" as *const u8 as *const libc::c_char
                                    as *mut libc::c_char,
                                type_0,
                                sock,
                                sock,
                                -(1 as libc::c_int),
                                (64 as libc::c_int * (32 as libc::c_int * 1024 as libc::c_int))
                                    as u_int,
                                (32 as libc::c_int * 1024 as libc::c_int) as u_int,
                                0 as libc::c_int,
                                b"port listener\0" as *const u8 as *const libc::c_char,
                                1 as libc::c_int,
                            );
                            (*c).path = xstrdup(host);
                            (*c).host_port = (*fwd).connect_port;
                            (*c).listening_addr = if addr.is_null() {
                                0 as *mut libc::c_char
                            } else {
                                xstrdup(addr)
                            };
                            if (*fwd).listen_port == 0 as libc::c_int
                                && !allocated_listen_port.is_null()
                                && (*ssh).compat & 0x8000000 as libc::c_int == 0
                            {
                                (*c).listening_port = *allocated_listen_port;
                            } else {
                                (*c).listening_port = (*fwd).listen_port;
                            }
                            success = 1 as libc::c_int;
                        }
                    }
                }
            }
            _ => {}
        }
        ai = (*ai).ai_next;
    }
    if success == 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 33], &[libc::c_char; 33]>(
                b"channel_setup_fwd_listener_tcpip\0",
            ))
            .as_ptr(),
            3873 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"cannot listen to port: %d\0" as *const u8 as *const libc::c_char,
            (*fwd).listen_port,
        );
    }
    freeaddrinfo(aitop);
    return success;
}
unsafe extern "C" fn channel_setup_fwd_listener_streamlocal(
    mut ssh: *mut ssh,
    mut type_0: libc::c_int,
    mut fwd: *mut Forward,
    mut fwd_opts: *mut ForwardOptions,
) -> libc::c_int {
    let mut _sunaddr: sockaddr_un = sockaddr_un {
        sun_family: 0,
        sun_path: [0; 108],
    };
    let mut path: *const libc::c_char = 0 as *const libc::c_char;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut port: libc::c_int = 0;
    let mut sock: libc::c_int = 0;
    let mut omask: mode_t = 0;
    match type_0 {
        18 => {
            if !((*fwd).connect_path).is_null() {
                if strlen((*fwd).connect_path)
                    > ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong
                {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 39], &[libc::c_char; 39]>(
                            b"channel_setup_fwd_listener_streamlocal\0",
                        ))
                        .as_ptr(),
                        3893 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Local connecting path too long: %s\0" as *const u8 as *const libc::c_char,
                        (*fwd).connect_path,
                    );
                    return 0 as libc::c_int;
                }
                path = (*fwd).connect_path;
                port = -(2 as libc::c_int);
            } else {
                if ((*fwd).connect_host).is_null() {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 39], &[libc::c_char; 39]>(
                            b"channel_setup_fwd_listener_streamlocal\0",
                        ))
                        .as_ptr(),
                        3900 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"No forward host name.\0" as *const u8 as *const libc::c_char,
                    );
                    return 0 as libc::c_int;
                }
                if strlen((*fwd).connect_host) >= 1025 as libc::c_int as libc::c_ulong {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 39], &[libc::c_char; 39]>(
                            b"channel_setup_fwd_listener_streamlocal\0",
                        ))
                        .as_ptr(),
                        3904 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Forward host name too long.\0" as *const u8 as *const libc::c_char,
                    );
                    return 0 as libc::c_int;
                }
                path = (*fwd).connect_host;
                port = (*fwd).connect_port;
            }
        }
        19 => {
            path = (*fwd).listen_path;
            port = -(2 as libc::c_int);
        }
        _ => {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 39], &[libc::c_char; 39]>(
                    b"channel_setup_fwd_listener_streamlocal\0",
                ))
                .as_ptr(),
                3916 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"unexpected channel type %d\0" as *const u8 as *const libc::c_char,
                type_0,
            );
            return 0 as libc::c_int;
        }
    }
    if ((*fwd).listen_path).is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 39], &[libc::c_char; 39]>(
                b"channel_setup_fwd_listener_streamlocal\0",
            ))
            .as_ptr(),
            3921 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"No forward path name.\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if strlen((*fwd).listen_path) > ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 39], &[libc::c_char; 39]>(
                b"channel_setup_fwd_listener_streamlocal\0",
            ))
            .as_ptr(),
            3925 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Local listening path too long: %s\0" as *const u8 as *const libc::c_char,
            (*fwd).listen_path,
        );
        return 0 as libc::c_int;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 39], &[libc::c_char; 39]>(
            b"channel_setup_fwd_listener_streamlocal\0",
        ))
        .as_ptr(),
        3929 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"type %d path %s\0" as *const u8 as *const libc::c_char,
        type_0,
        (*fwd).listen_path,
    );
    omask = umask((*fwd_opts).streamlocal_bind_mask);
    sock = unix_listener(
        (*fwd).listen_path,
        128 as libc::c_int,
        (*fwd_opts).streamlocal_bind_unlink,
    );
    umask(omask);
    if sock < 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 39], &[libc::c_char; 39]>(
            b"channel_setup_fwd_listener_streamlocal\0",
        ))
        .as_ptr(),
        3939 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Local forwarding listening on path %s.\0" as *const u8 as *const libc::c_char,
        (*fwd).listen_path,
    );
    c = channel_new(
        ssh,
        b"unix-listener\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        type_0,
        sock,
        sock,
        -(1 as libc::c_int),
        (64 as libc::c_int * (32 as libc::c_int * 1024 as libc::c_int)) as u_int,
        (32 as libc::c_int * 1024 as libc::c_int) as u_int,
        0 as libc::c_int,
        b"unix listener\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    (*c).path = xstrdup(path);
    (*c).host_port = port;
    (*c).listening_port = -(2 as libc::c_int);
    (*c).listening_addr = xstrdup((*fwd).listen_path);
    return 1 as libc::c_int;
}
unsafe extern "C" fn channel_cancel_rport_listener_tcpip(
    mut ssh: *mut ssh,
    mut host: *const libc::c_char,
    mut port: u_short,
) -> libc::c_int {
    let mut i: u_int = 0;
    let mut found: libc::c_int = 0 as libc::c_int;
    i = 0 as libc::c_int as u_int;
    while i < (*(*ssh).chanctxt).channels_alloc {
        let mut c: *mut Channel = *((*(*ssh).chanctxt).channels).offset(i as isize);
        if !(c.is_null() || (*c).type_0 != 11 as libc::c_int) {
            if strcmp((*c).path, host) == 0 as libc::c_int
                && (*c).listening_port == port as libc::c_int
            {
                sshlog(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 36], &[libc::c_char; 36]>(
                        b"channel_cancel_rport_listener_tcpip\0",
                    ))
                    .as_ptr(),
                    3964 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"close channel %d\0" as *const u8 as *const libc::c_char,
                    i,
                );
                channel_free(ssh, c);
                found = 1 as libc::c_int;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return found;
}
unsafe extern "C" fn channel_cancel_rport_listener_streamlocal(
    mut ssh: *mut ssh,
    mut path: *const libc::c_char,
) -> libc::c_int {
    let mut i: u_int = 0;
    let mut found: libc::c_int = 0 as libc::c_int;
    i = 0 as libc::c_int as u_int;
    while i < (*(*ssh).chanctxt).channels_alloc {
        let mut c: *mut Channel = *((*(*ssh).chanctxt).channels).offset(i as isize);
        if !(c.is_null() || (*c).type_0 != 19 as libc::c_int) {
            if !((*c).path).is_null() {
                if strcmp((*c).path, path) == 0 as libc::c_int {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 42], &[libc::c_char; 42]>(
                            b"channel_cancel_rport_listener_streamlocal\0",
                        ))
                        .as_ptr(),
                        3986 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        0 as *const libc::c_char,
                        b"close channel %d\0" as *const u8 as *const libc::c_char,
                        i,
                    );
                    channel_free(ssh, c);
                    found = 1 as libc::c_int;
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return found;
}
pub unsafe extern "C" fn channel_cancel_rport_listener(
    mut ssh: *mut ssh,
    mut fwd: *mut Forward,
) -> libc::c_int {
    if !((*fwd).listen_path).is_null() {
        return channel_cancel_rport_listener_streamlocal(ssh, (*fwd).listen_path);
    } else {
        return channel_cancel_rport_listener_tcpip(
            ssh,
            (*fwd).listen_host,
            (*fwd).listen_port as u_short,
        );
    };
}
unsafe extern "C" fn channel_cancel_lport_listener_tcpip(
    mut ssh: *mut ssh,
    mut lhost: *const libc::c_char,
    mut lport: u_short,
    mut cport: libc::c_int,
    mut fwd_opts: *mut ForwardOptions,
) -> libc::c_int {
    let mut i: u_int = 0;
    let mut found: libc::c_int = 0 as libc::c_int;
    let mut addr: *const libc::c_char = channel_fwd_bind_addr(
        ssh,
        lhost,
        0 as *mut libc::c_int,
        1 as libc::c_int,
        fwd_opts,
    );
    let mut current_block_5: u64;
    i = 0 as libc::c_int as u_int;
    while i < (*(*ssh).chanctxt).channels_alloc {
        let mut c: *mut Channel = *((*(*ssh).chanctxt).channels).offset(i as isize);
        if !(c.is_null() || (*c).type_0 != 2 as libc::c_int) {
            if !((*c).listening_port != lport as libc::c_int) {
                if cport == -(1 as libc::c_int) {
                    if (*c).host_port == 0 as libc::c_int {
                        current_block_5 = 6239978542346980191;
                    } else {
                        current_block_5 = 13183875560443969876;
                    }
                } else if (*c).host_port != cport {
                    current_block_5 = 6239978542346980191;
                } else {
                    current_block_5 = 13183875560443969876;
                }
                match current_block_5 {
                    6239978542346980191 => {}
                    _ => {
                        if !(((*c).listening_addr).is_null() && !addr.is_null()
                            || !((*c).listening_addr).is_null() && addr.is_null())
                        {
                            if addr.is_null()
                                || strcmp((*c).listening_addr, addr) == 0 as libc::c_int
                            {
                                sshlog(
                                    b"channels.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 36], &[libc::c_char; 36]>(
                                        b"channel_cancel_lport_listener_tcpip\0",
                                    ))
                                    .as_ptr(),
                                    4034 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG2,
                                    0 as *const libc::c_char,
                                    b"close channel %d\0" as *const u8 as *const libc::c_char,
                                    i,
                                );
                                channel_free(ssh, c);
                                found = 1 as libc::c_int;
                            }
                        }
                    }
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return found;
}
unsafe extern "C" fn channel_cancel_lport_listener_streamlocal(
    mut ssh: *mut ssh,
    mut path: *const libc::c_char,
) -> libc::c_int {
    let mut i: u_int = 0;
    let mut found: libc::c_int = 0 as libc::c_int;
    if path.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 42], &[libc::c_char; 42]>(
                b"channel_cancel_lport_listener_streamlocal\0",
            ))
            .as_ptr(),
            4050 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no path specified.\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as u_int;
    while i < (*(*ssh).chanctxt).channels_alloc {
        let mut c: *mut Channel = *((*(*ssh).chanctxt).channels).offset(i as isize);
        if !(c.is_null() || (*c).type_0 != 18 as libc::c_int) {
            if !((*c).listening_addr).is_null() {
                if strcmp((*c).listening_addr, path) == 0 as libc::c_int {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 42], &[libc::c_char; 42]>(
                            b"channel_cancel_lport_listener_streamlocal\0",
                        ))
                        .as_ptr(),
                        4061 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        0 as *const libc::c_char,
                        b"close channel %d\0" as *const u8 as *const libc::c_char,
                        i,
                    );
                    channel_free(ssh, c);
                    found = 1 as libc::c_int;
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return found;
}
pub unsafe extern "C" fn channel_cancel_lport_listener(
    mut ssh: *mut ssh,
    mut fwd: *mut Forward,
    mut cport: libc::c_int,
    mut fwd_opts: *mut ForwardOptions,
) -> libc::c_int {
    if !((*fwd).listen_path).is_null() {
        return channel_cancel_lport_listener_streamlocal(ssh, (*fwd).listen_path);
    } else {
        return channel_cancel_lport_listener_tcpip(
            ssh,
            (*fwd).listen_host,
            (*fwd).listen_port as u_short,
            cport,
            fwd_opts,
        );
    };
}
pub unsafe extern "C" fn channel_setup_local_fwd_listener(
    mut ssh: *mut ssh,
    mut fwd: *mut Forward,
    mut fwd_opts: *mut ForwardOptions,
) -> libc::c_int {
    if !((*fwd).listen_path).is_null() {
        return channel_setup_fwd_listener_streamlocal(ssh, 18 as libc::c_int, fwd, fwd_opts);
    } else {
        return channel_setup_fwd_listener_tcpip(
            ssh,
            2 as libc::c_int,
            fwd,
            0 as *mut libc::c_int,
            fwd_opts,
        );
    };
}
unsafe extern "C" fn remote_open_match(
    mut allowed_open: *mut permission,
    mut fwd: *mut Forward,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    let mut lhost: *mut libc::c_char = 0 as *mut libc::c_char;
    if !((*fwd).listen_path).is_null() {
        return 1 as libc::c_int;
    }
    if ((*fwd).listen_host).is_null() || ((*allowed_open).listen_host).is_null() {
        return 0 as libc::c_int;
    }
    if (*allowed_open).listen_port != 0 as libc::c_int
        && (*allowed_open).listen_port != (*fwd).listen_port
    {
        return 0 as libc::c_int;
    }
    lhost = xstrdup((*fwd).listen_host);
    lowercase(lhost);
    ret = match_pattern(lhost, (*allowed_open).listen_host);
    free(lhost as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn check_rfwd_permission(
    mut ssh: *mut ssh,
    mut fwd: *mut Forward,
) -> libc::c_int {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut pset: *mut permission_set = &mut (*sc).remote_perms;
    let mut i: u_int = 0;
    let mut permit: u_int = 0;
    let mut permit_adm: u_int = 1 as libc::c_int as u_int;
    let mut perm: *mut permission = 0 as *mut permission;
    permit = (*pset).all_permitted as u_int;
    if permit == 0 {
        i = 0 as libc::c_int as u_int;
        while i < (*pset).num_permitted_user {
            perm = &mut *((*pset).permitted_user).offset(i as isize) as *mut permission;
            if remote_open_match(perm, fwd) != 0 {
                permit = 1 as libc::c_int as u_int;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
    }
    if (*pset).num_permitted_admin > 0 as libc::c_int as libc::c_uint {
        permit_adm = 0 as libc::c_int as u_int;
        i = 0 as libc::c_int as u_int;
        while i < (*pset).num_permitted_admin {
            perm = &mut *((*pset).permitted_admin).offset(i as isize) as *mut permission;
            if remote_open_match(perm, fwd) != 0 {
                permit_adm = 1 as libc::c_int as u_int;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
    }
    return (permit != 0 && permit_adm != 0) as libc::c_int;
}
pub unsafe extern "C" fn channel_setup_remote_fwd_listener(
    mut ssh: *mut ssh,
    mut fwd: *mut Forward,
    mut allocated_listen_port: *mut libc::c_int,
    mut fwd_opts: *mut ForwardOptions,
) -> libc::c_int {
    if check_rfwd_permission(ssh, fwd) == 0 {
        ssh_packet_send_debug(
            ssh,
            b"port forwarding refused\0" as *const u8 as *const libc::c_char,
        );
        if !((*fwd).listen_path).is_null() {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<
                    &[u8; 34],
                    &[libc::c_char; 34],
                >(b"channel_setup_remote_fwd_listener\0"))
                    .as_ptr(),
                4173 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Received request from %.100s port %d to remote forward to path \"%.100s\", but the request was denied.\0"
                    as *const u8 as *const libc::c_char,
                ssh_remote_ipaddr(ssh),
                ssh_remote_port(ssh),
                (*fwd).listen_path,
            );
        } else if !((*fwd).listen_host).is_null() {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<
                    &[u8; 34],
                    &[libc::c_char; 34],
                >(b"channel_setup_remote_fwd_listener\0"))
                    .as_ptr(),
                4179 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Received request from %.100s port %d to remote forward to host %.100s port %d, but the request was denied.\0"
                    as *const u8 as *const libc::c_char,
                ssh_remote_ipaddr(ssh),
                ssh_remote_port(ssh),
                (*fwd).listen_host,
                (*fwd).listen_port,
            );
        } else {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<
                    &[u8; 34],
                    &[libc::c_char; 34],
                >(b"channel_setup_remote_fwd_listener\0"))
                    .as_ptr(),
                4183 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Received request from %.100s port %d to remote forward, but the request was denied.\0"
                    as *const u8 as *const libc::c_char,
                ssh_remote_ipaddr(ssh),
                ssh_remote_port(ssh),
            );
        }
        return 0 as libc::c_int;
    }
    if !((*fwd).listen_path).is_null() {
        return channel_setup_fwd_listener_streamlocal(ssh, 19 as libc::c_int, fwd, fwd_opts);
    } else {
        return channel_setup_fwd_listener_tcpip(
            ssh,
            11 as libc::c_int,
            fwd,
            allocated_listen_port,
            fwd_opts,
        );
    };
}
unsafe extern "C" fn channel_rfwd_bind_host(
    mut listen_host: *const libc::c_char,
) -> *const libc::c_char {
    if listen_host.is_null() {
        return b"localhost\0" as *const u8 as *const libc::c_char;
    } else if *listen_host as libc::c_int == '\0' as i32
        || strcmp(listen_host, b"*\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
    {
        return b"\0" as *const u8 as *const libc::c_char;
    } else {
        return listen_host;
    };
}
pub unsafe extern "C" fn channel_request_remote_forwarding(
    mut ssh: *mut ssh,
    mut fwd: *mut Forward,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut idx: libc::c_int = -(1 as libc::c_int);
    let mut host_to_connect: *const libc::c_char = 0 as *const libc::c_char;
    let mut listen_host: *const libc::c_char = 0 as *const libc::c_char;
    let mut listen_path: *const libc::c_char = 0 as *const libc::c_char;
    let mut port_to_connect: libc::c_int = 0;
    let mut listen_port: libc::c_int = 0;
    if !((*fwd).listen_path).is_null() {
        r = sshpkt_start(ssh, 80 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshpkt_put_cstring(
                    ssh,
                    b"streamlocal-forward@openssh.com\0" as *const u8 as *const libc::c_char
                        as *const libc::c_void,
                );
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_put_u8(ssh, 1 as libc::c_int as u_char);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_put_cstring(ssh, (*fwd).listen_path as *const libc::c_void);
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
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                    b"channel_request_remote_forwarding\0",
                ))
                .as_ptr(),
                4233 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"request streamlocal\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        r = sshpkt_start(ssh, 80 as libc::c_int as u_char);
        if r != 0 as libc::c_int
            || {
                r = sshpkt_put_cstring(
                    ssh,
                    b"tcpip-forward\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                );
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_put_u8(ssh, 1 as libc::c_int as u_char);
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_put_cstring(
                    ssh,
                    channel_rfwd_bind_host((*fwd).listen_host) as *const libc::c_void,
                );
                r != 0 as libc::c_int
            }
            || {
                r = sshpkt_put_u32(ssh, (*fwd).listen_port as u_int32_t);
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
            sshfatal(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
                    b"channel_request_remote_forwarding\0",
                ))
                .as_ptr(),
                4243 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"request tcpip-forward\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    success = 1 as libc::c_int;
    if success != 0 {
        listen_path = 0 as *const libc::c_char;
        listen_host = listen_path;
        host_to_connect = listen_host;
        listen_port = 0 as libc::c_int;
        port_to_connect = listen_port;
        if !((*fwd).connect_path).is_null() {
            host_to_connect = (*fwd).connect_path;
            port_to_connect = -(2 as libc::c_int);
        } else {
            host_to_connect = (*fwd).connect_host;
            port_to_connect = (*fwd).connect_port;
        }
        if !((*fwd).listen_path).is_null() {
            listen_path = (*fwd).listen_path;
            listen_port = -(2 as libc::c_int);
        } else {
            listen_host = (*fwd).listen_host;
            listen_port = (*fwd).listen_port;
        }
        idx = permission_set_add(
            ssh,
            0x101 as libc::c_int,
            (1 as libc::c_int) << 1 as libc::c_int,
            host_to_connect,
            port_to_connect,
            listen_host,
            listen_path,
            listen_port,
            0 as *mut Channel,
        );
    }
    return idx;
}
unsafe extern "C" fn open_match(
    mut allowed_open: *mut permission,
    mut requestedhost: *const libc::c_char,
    mut requestedport: libc::c_int,
) -> libc::c_int {
    if ((*allowed_open).host_to_connect).is_null() {
        return 0 as libc::c_int;
    }
    if (*allowed_open).port_to_connect != 0 as libc::c_int
        && (*allowed_open).port_to_connect != requestedport
    {
        return 0 as libc::c_int;
    }
    if strcmp(
        (*allowed_open).host_to_connect,
        b"*\0" as *const u8 as *const libc::c_char,
    ) != 0 as libc::c_int
        && strcmp((*allowed_open).host_to_connect, requestedhost) != 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn open_listen_match_tcpip(
    mut allowed_open: *mut permission,
    mut requestedhost: *const libc::c_char,
    mut requestedport: u_short,
    mut translate: libc::c_int,
) -> libc::c_int {
    let mut allowed_host: *const libc::c_char = 0 as *const libc::c_char;
    if ((*allowed_open).host_to_connect).is_null() {
        return 0 as libc::c_int;
    }
    if (*allowed_open).listen_port != requestedport as libc::c_int {
        return 0 as libc::c_int;
    }
    if translate == 0 && ((*allowed_open).listen_host).is_null() && requestedhost.is_null() {
        return 1 as libc::c_int;
    }
    allowed_host = if translate != 0 {
        channel_rfwd_bind_host((*allowed_open).listen_host)
    } else {
        (*allowed_open).listen_host as *const libc::c_char
    };
    if allowed_host.is_null()
        || requestedhost.is_null()
        || strcmp(allowed_host, requestedhost) != 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn open_listen_match_streamlocal(
    mut allowed_open: *mut permission,
    mut requestedpath: *const libc::c_char,
) -> libc::c_int {
    if ((*allowed_open).host_to_connect).is_null() {
        return 0 as libc::c_int;
    }
    if (*allowed_open).listen_port != -(2 as libc::c_int) {
        return 0 as libc::c_int;
    }
    if ((*allowed_open).listen_path).is_null()
        || strcmp((*allowed_open).listen_path, requestedpath) != 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn channel_request_rforward_cancel_tcpip(
    mut ssh: *mut ssh,
    mut host: *const libc::c_char,
    mut port: u_short,
) -> libc::c_int {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut pset: *mut permission_set = &mut (*sc).local_perms;
    let mut r: libc::c_int = 0;
    let mut i: u_int = 0;
    let mut perm: *mut permission = 0 as *mut permission;
    i = 0 as libc::c_int as u_int;
    while i < (*pset).num_permitted_user {
        perm = &mut *((*pset).permitted_user).offset(i as isize) as *mut permission;
        if open_listen_match_tcpip(perm, host, port, 0 as libc::c_int) != 0 {
            break;
        }
        perm = 0 as *mut permission;
        i = i.wrapping_add(1);
        i;
    }
    if perm.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 38], &[libc::c_char; 38]>(
                b"channel_request_rforward_cancel_tcpip\0",
            ))
            .as_ptr(),
            4350 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"requested forward not found\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    r = sshpkt_start(ssh, 80 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_cstring(
                ssh,
                b"cancel-tcpip-forward\0" as *const u8 as *const libc::c_char
                    as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u8(ssh, 0 as libc::c_int as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_cstring(ssh, channel_rfwd_bind_host(host) as *const libc::c_void);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, port as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 38], &[libc::c_char; 38]>(
                b"channel_request_rforward_cancel_tcpip\0",
            ))
            .as_ptr(),
            4359 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send cancel\0" as *const u8 as *const libc::c_char,
        );
    }
    fwd_perm_clear(perm);
    return 0 as libc::c_int;
}
unsafe extern "C" fn channel_request_rforward_cancel_streamlocal(
    mut ssh: *mut ssh,
    mut path: *const libc::c_char,
) -> libc::c_int {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut pset: *mut permission_set = &mut (*sc).local_perms;
    let mut r: libc::c_int = 0;
    let mut i: u_int = 0;
    let mut perm: *mut permission = 0 as *mut permission;
    i = 0 as libc::c_int as u_int;
    while i < (*pset).num_permitted_user {
        perm = &mut *((*pset).permitted_user).offset(i as isize) as *mut permission;
        if open_listen_match_streamlocal(perm, path) != 0 {
            break;
        }
        perm = 0 as *mut permission;
        i = i.wrapping_add(1);
        i;
    }
    if perm.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 44], &[libc::c_char; 44]>(
                b"channel_request_rforward_cancel_streamlocal\0",
            ))
            .as_ptr(),
            4386 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"requested forward not found\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    r = sshpkt_start(ssh, 80 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_cstring(
                ssh,
                b"cancel-streamlocal-forward@openssh.com\0" as *const u8 as *const libc::c_char
                    as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u8(ssh, 0 as libc::c_int as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_cstring(ssh, path as *const libc::c_void);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 44], &[libc::c_char; 44]>(
                b"channel_request_rforward_cancel_streamlocal\0",
            ))
            .as_ptr(),
            4395 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send cancel\0" as *const u8 as *const libc::c_char,
        );
    }
    fwd_perm_clear(perm);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn channel_request_rforward_cancel(
    mut ssh: *mut ssh,
    mut fwd: *mut Forward,
) -> libc::c_int {
    if !((*fwd).listen_path).is_null() {
        return channel_request_rforward_cancel_streamlocal(ssh, (*fwd).listen_path);
    } else {
        return channel_request_rforward_cancel_tcpip(
            ssh,
            (*fwd).listen_host,
            (if (*fwd).listen_port != 0 {
                (*fwd).listen_port
            } else {
                (*fwd).allocated_port
            }) as u_short,
        );
    };
}
pub unsafe extern "C" fn channel_permit_all(mut ssh: *mut ssh, mut where_0: libc::c_int) {
    let mut pset: *mut permission_set = permission_set_get(ssh, where_0);
    if (*pset).num_permitted_user == 0 as libc::c_int as libc::c_uint {
        (*pset).all_permitted = 1 as libc::c_int;
    }
}
pub unsafe extern "C" fn channel_add_permission(
    mut ssh: *mut ssh,
    mut who: libc::c_int,
    mut where_0: libc::c_int,
    mut host: *mut libc::c_char,
    mut port: libc::c_int,
) {
    let mut local: libc::c_int = (where_0 == (1 as libc::c_int) << 1 as libc::c_int) as libc::c_int;
    let mut pset: *mut permission_set = permission_set_get(ssh, where_0);
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"channel_add_permission\0"))
            .as_ptr(),
        4443 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"allow %s forwarding to host %s port %d\0" as *const u8 as *const libc::c_char,
        fwd_ident(who, where_0),
        host,
        port,
    );
    permission_set_add(
        ssh,
        who,
        where_0,
        if local != 0 {
            host
        } else {
            0 as *mut libc::c_char
        },
        if local != 0 { port } else { 0 as libc::c_int },
        if local != 0 {
            0 as *mut libc::c_char
        } else {
            host
        },
        0 as *const libc::c_char,
        if local != 0 { 0 as libc::c_int } else { port },
        0 as *mut Channel,
    );
    (*pset).all_permitted = 0 as libc::c_int;
}
pub unsafe extern "C" fn channel_disable_admin(mut ssh: *mut ssh, mut where_0: libc::c_int) {
    channel_clear_permission(ssh, 0x100 as libc::c_int, where_0);
    permission_set_add(
        ssh,
        0x100 as libc::c_int,
        where_0,
        0 as *const libc::c_char,
        0 as libc::c_int,
        0 as *const libc::c_char,
        0 as *const libc::c_char,
        0 as libc::c_int,
        0 as *mut Channel,
    );
}
pub unsafe extern "C" fn channel_clear_permission(
    mut ssh: *mut ssh,
    mut who: libc::c_int,
    mut where_0: libc::c_int,
) {
    let mut permp: *mut *mut permission = 0 as *mut *mut permission;
    let mut npermp: *mut u_int = 0 as *mut u_int;
    permission_set_get_array(ssh, who, where_0, &mut permp, &mut npermp);
    *permp = xrecallocarray(
        *permp as *mut libc::c_void,
        *npermp as size_t,
        0 as libc::c_int as size_t,
        ::core::mem::size_of::<permission>() as libc::c_ulong,
    ) as *mut permission;
    *npermp = 0 as libc::c_int as u_int;
}
pub unsafe extern "C" fn channel_update_permission(
    mut ssh: *mut ssh,
    mut idx: libc::c_int,
    mut newport: libc::c_int,
) {
    let mut pset: *mut permission_set = &mut (*(*ssh).chanctxt).local_perms;
    if idx < 0 as libc::c_int || idx as u_int >= (*pset).num_permitted_user {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"channel_update_permission\0",
            ))
            .as_ptr(),
            4491 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"index out of range: %d num_permitted_user %d\0" as *const u8 as *const libc::c_char,
            idx,
            (*pset).num_permitted_user,
        );
        return;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"channel_update_permission\0"))
            .as_ptr(),
        4498 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"%s allowed port %d for forwarding to host %s port %d\0" as *const u8
            as *const libc::c_char,
        if newport > 0 as libc::c_int {
            b"Updating\0" as *const u8 as *const libc::c_char
        } else {
            b"Removing\0" as *const u8 as *const libc::c_char
        },
        newport,
        (*((*pset).permitted_user).offset(idx as isize)).host_to_connect,
        (*((*pset).permitted_user).offset(idx as isize)).port_to_connect,
    );
    if newport <= 0 as libc::c_int {
        fwd_perm_clear(&mut *((*pset).permitted_user).offset(idx as isize));
    } else {
        (*((*pset).permitted_user).offset(idx as isize)).listen_port =
            if (*ssh).compat & 0x8000000 as libc::c_int != 0 {
                0 as libc::c_int
            } else {
                newport
            };
    };
}
pub unsafe extern "C" fn permitopen_port(mut p: *const libc::c_char) -> libc::c_int {
    let mut port: libc::c_int = 0;
    if strcmp(p, b"*\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    port = a2port(p);
    if port > 0 as libc::c_int {
        return port;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn connect_next(mut cctx: *mut channel_connect) -> libc::c_int {
    let mut sock: libc::c_int = 0;
    let mut saved_errno: libc::c_int = 0;
    let mut sunaddr: *mut sockaddr_un = 0 as *mut sockaddr_un;
    let mut ntop: [libc::c_char; 1025] = [0; 1025];
    let mut strport: [libc::c_char; 108] = [0; 108];
    let mut current_block_18: u64;
    while !((*cctx).ai).is_null() {
        match (*(*cctx).ai).ai_family {
            1 => {
                sunaddr = (*(*cctx).ai).ai_addr as *mut sockaddr_un;
                strlcpy(
                    ntop.as_mut_ptr(),
                    b"unix\0" as *const u8 as *const libc::c_char,
                    ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
                );
                strlcpy(
                    strport.as_mut_ptr(),
                    ((*sunaddr).sun_path).as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong,
                );
                current_block_18 = 11812396948646013369;
            }
            2 | 10 => {
                if getnameinfo(
                    (*(*cctx).ai).ai_addr,
                    (*(*cctx).ai).ai_addrlen,
                    ntop.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as socklen_t,
                    strport.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong as socklen_t,
                    1 as libc::c_int | 2 as libc::c_int,
                ) != 0 as libc::c_int
                {
                    sshlog(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                            b"connect_next\0",
                        ))
                        .as_ptr(),
                        4542 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"getnameinfo failed\0" as *const u8 as *const libc::c_char,
                    );
                    current_block_18 = 8258075665625361029;
                } else {
                    current_block_18 = 11812396948646013369;
                }
            }
            _ => {
                current_block_18 = 8258075665625361029;
            }
        }
        match current_block_18 {
            11812396948646013369 => {
                sshlog(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"connect_next\0"))
                        .as_ptr(),
                    4550 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"start for host %.100s ([%.100s]:%s)\0" as *const u8 as *const libc::c_char,
                    (*cctx).host,
                    ntop.as_mut_ptr(),
                    strport.as_mut_ptr(),
                );
                sock = socket(
                    (*(*cctx).ai).ai_family,
                    (*(*cctx).ai).ai_socktype,
                    (*(*cctx).ai).ai_protocol,
                );
                if sock == -(1 as libc::c_int) {
                    if ((*(*cctx).ai).ai_next).is_null() {
                        sshlog(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"connect_next\0",
                            ))
                            .as_ptr(),
                            4554 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"socket: %.100s\0" as *const u8 as *const libc::c_char,
                            strerror(*__errno_location()),
                        );
                    } else {
                        sshlog(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"connect_next\0",
                            ))
                            .as_ptr(),
                            4556 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_VERBOSE,
                            0 as *const libc::c_char,
                            b"socket: %.100s\0" as *const u8 as *const libc::c_char,
                            strerror(*__errno_location()),
                        );
                    }
                } else {
                    if set_nonblock(sock) == -(1 as libc::c_int) {
                        sshfatal(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"connect_next\0",
                            ))
                            .as_ptr(),
                            4560 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"set_nonblock(%d)\0" as *const u8 as *const libc::c_char,
                            sock,
                        );
                    }
                    if connect(
                        sock,
                        __CONST_SOCKADDR_ARG {
                            __sockaddr__: (*(*cctx).ai).ai_addr,
                        },
                        (*(*cctx).ai).ai_addrlen,
                    ) == -(1 as libc::c_int)
                        && *__errno_location() != 115 as libc::c_int
                    {
                        sshlog(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"connect_next\0",
                            ))
                            .as_ptr(),
                            4564 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"host %.100s ([%.100s]:%s): %.100s\0" as *const u8
                                as *const libc::c_char,
                            (*cctx).host,
                            ntop.as_mut_ptr(),
                            strport.as_mut_ptr(),
                            strerror(*__errno_location()),
                        );
                        saved_errno = *__errno_location();
                        close(sock);
                        *__errno_location() = saved_errno;
                    } else {
                        if (*(*cctx).ai).ai_family != 1 as libc::c_int {
                            set_nodelay(sock);
                        }
                        sshlog(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(
                                b"connect_next\0",
                            ))
                            .as_ptr(),
                            4573 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"connect host %.100s ([%.100s]:%s) in progress, fd=%d\0" as *const u8
                                as *const libc::c_char,
                            (*cctx).host,
                            ntop.as_mut_ptr(),
                            strport.as_mut_ptr(),
                            sock,
                        );
                        (*cctx).ai = (*(*cctx).ai).ai_next;
                        return sock;
                    }
                }
            }
            _ => {}
        }
        (*cctx).ai = (*(*cctx).ai).ai_next;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn channel_connect_ctx_free(mut cctx: *mut channel_connect) {
    free((*cctx).host as *mut libc::c_void);
    if !((*cctx).aitop).is_null() {
        if (*(*cctx).aitop).ai_family == 1 as libc::c_int {
            free((*cctx).aitop as *mut libc::c_void);
        } else {
            freeaddrinfo((*cctx).aitop);
        }
    }
    memset(
        cctx as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<channel_connect>() as libc::c_ulong,
    );
}
unsafe extern "C" fn connect_to_helper(
    mut ssh: *mut ssh,
    mut name: *const libc::c_char,
    mut port: libc::c_int,
    mut socktype: libc::c_int,
    mut _ctype: *mut libc::c_char,
    mut _rname: *mut libc::c_char,
    mut cctx: *mut channel_connect,
    mut reason: *mut libc::c_int,
    mut errmsg: *mut *const libc::c_char,
) -> libc::c_int {
    let mut hints: addrinfo = addrinfo {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: 0 as *mut sockaddr,
        ai_canonname: 0 as *mut libc::c_char,
        ai_next: 0 as *mut addrinfo,
    };
    let mut gaierr: libc::c_int = 0;
    let mut sock: libc::c_int = -(1 as libc::c_int);
    let mut strport: [libc::c_char; 32] = [0; 32];
    if port == -(2 as libc::c_int) {
        let mut sunaddr: *mut sockaddr_un = 0 as *mut sockaddr_un;
        let mut ai: *mut addrinfo = 0 as *mut addrinfo;
        if strlen(name) > ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"connect_to_helper\0"))
                    .as_ptr(),
                4612 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"%.100s: %.100s\0" as *const u8 as *const libc::c_char,
                name,
                strerror(36 as libc::c_int),
            );
            return -(1 as libc::c_int);
        }
        ai = xmalloc(
            (::core::mem::size_of::<addrinfo>() as libc::c_ulong)
                .wrapping_add(::core::mem::size_of::<sockaddr_un>() as libc::c_ulong),
        ) as *mut addrinfo;
        memset(
            ai as *mut libc::c_void,
            0 as libc::c_int,
            (::core::mem::size_of::<addrinfo>() as libc::c_ulong)
                .wrapping_add(::core::mem::size_of::<sockaddr_un>() as libc::c_ulong),
        );
        (*ai).ai_addr = ai.offset(1 as libc::c_int as isize) as *mut sockaddr;
        (*ai).ai_addrlen = ::core::mem::size_of::<sockaddr_un>() as libc::c_ulong as socklen_t;
        (*ai).ai_family = 1 as libc::c_int;
        (*ai).ai_socktype = socktype;
        (*ai).ai_protocol = 0 as libc::c_int;
        sunaddr = (*ai).ai_addr as *mut sockaddr_un;
        (*sunaddr).sun_family = 1 as libc::c_int as sa_family_t;
        strlcpy(
            ((*sunaddr).sun_path).as_mut_ptr(),
            name,
            ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong,
        );
        (*cctx).aitop = ai;
    } else {
        memset(
            &mut hints as *mut addrinfo as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
        );
        hints.ai_family = (*(*ssh).chanctxt).IPv4or6;
        hints.ai_socktype = socktype;
        snprintf(
            strport.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
            b"%d\0" as *const u8 as *const libc::c_char,
            port,
        );
        gaierr = getaddrinfo(name, strport.as_mut_ptr(), &mut hints, &mut (*cctx).aitop);
        if gaierr != 0 as libc::c_int {
            if !errmsg.is_null() {
                *errmsg = ssh_gai_strerror(gaierr);
            }
            if !reason.is_null() {
                *reason = 2 as libc::c_int;
            }
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"connect_to_helper\0"))
                    .as_ptr(),
                4644 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"connect_to %.100s: unknown host (%s)\0" as *const u8 as *const libc::c_char,
                name,
                ssh_gai_strerror(gaierr),
            );
            return -(1 as libc::c_int);
        }
    }
    (*cctx).host = xstrdup(name);
    (*cctx).port = port;
    (*cctx).ai = (*cctx).aitop;
    sock = connect_next(cctx);
    if sock == -(1 as libc::c_int) {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"connect_to_helper\0"))
                .as_ptr(),
            4655 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"connect to %.100s port %d failed: %s\0" as *const u8 as *const libc::c_char,
            name,
            port,
            strerror(*__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    return sock;
}
unsafe extern "C" fn connect_to(
    mut ssh: *mut ssh,
    mut host: *const libc::c_char,
    mut port: libc::c_int,
    mut ctype: *mut libc::c_char,
    mut rname: *mut libc::c_char,
) -> *mut Channel {
    let mut cctx: channel_connect = channel_connect {
        host: 0 as *mut libc::c_char,
        port: 0,
        ai: 0 as *mut addrinfo,
        aitop: 0 as *mut addrinfo,
    };
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut sock: libc::c_int = 0;
    memset(
        &mut cctx as *mut channel_connect as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<channel_connect>() as libc::c_ulong,
    );
    sock = connect_to_helper(
        ssh,
        host,
        port,
        SOCK_STREAM as libc::c_int,
        ctype,
        rname,
        &mut cctx,
        0 as *mut libc::c_int,
        0 as *mut *const libc::c_char,
    );
    if sock == -(1 as libc::c_int) {
        channel_connect_ctx_free(&mut cctx);
        return 0 as *mut Channel;
    }
    c = channel_new(
        ssh,
        ctype,
        12 as libc::c_int,
        sock,
        sock,
        -(1 as libc::c_int),
        (64 as libc::c_int * (32 as libc::c_int * 1024 as libc::c_int)) as u_int,
        (32 as libc::c_int * 1024 as libc::c_int) as u_int,
        0 as libc::c_int,
        rname,
        1 as libc::c_int,
    );
    (*c).host_port = port;
    (*c).path = xstrdup(host);
    (*c).connect_ctx = cctx;
    return c;
}
pub unsafe extern "C" fn channel_connect_by_listen_address(
    mut ssh: *mut ssh,
    mut listen_host: *const libc::c_char,
    mut listen_port: u_short,
    mut ctype: *mut libc::c_char,
    mut rname: *mut libc::c_char,
) -> *mut Channel {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut pset: *mut permission_set = &mut (*sc).local_perms;
    let mut i: u_int = 0;
    let mut perm: *mut permission = 0 as *mut permission;
    i = 0 as libc::c_int as u_int;
    while i < (*pset).num_permitted_user {
        perm = &mut *((*pset).permitted_user).offset(i as isize) as *mut permission;
        if open_listen_match_tcpip(perm, listen_host, listen_port, 1 as libc::c_int) != 0 {
            if !((*perm).downstream).is_null() {
                return (*perm).downstream;
            }
            if (*perm).port_to_connect == 0 as libc::c_int {
                return rdynamic_connect_prepare(ssh, ctype, rname);
            }
            return connect_to(
                ssh,
                (*perm).host_to_connect,
                (*perm).port_to_connect,
                ctype,
                rname,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 34], &[libc::c_char; 34]>(
            b"channel_connect_by_listen_address\0",
        ))
        .as_ptr(),
        4715 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"WARNING: Server requests forwarding for unknown listen_port %d\0" as *const u8
            as *const libc::c_char,
        listen_port as libc::c_int,
    );
    return 0 as *mut Channel;
}
pub unsafe extern "C" fn channel_connect_by_listen_path(
    mut ssh: *mut ssh,
    mut path: *const libc::c_char,
    mut ctype: *mut libc::c_char,
    mut rname: *mut libc::c_char,
) -> *mut Channel {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut pset: *mut permission_set = &mut (*sc).local_perms;
    let mut i: u_int = 0;
    let mut perm: *mut permission = 0 as *mut permission;
    i = 0 as libc::c_int as u_int;
    while i < (*pset).num_permitted_user {
        perm = &mut *((*pset).permitted_user).offset(i as isize) as *mut permission;
        if open_listen_match_streamlocal(perm, path) != 0 {
            return connect_to(
                ssh,
                (*perm).host_to_connect,
                (*perm).port_to_connect,
                ctype,
                rname,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
            b"channel_connect_by_listen_path\0",
        ))
        .as_ptr(),
        4737 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"WARNING: Server requests forwarding for unknown path %.100s\0" as *const u8
            as *const libc::c_char,
        path,
    );
    return 0 as *mut Channel;
}
pub unsafe extern "C" fn channel_connect_to_port(
    mut ssh: *mut ssh,
    mut host: *const libc::c_char,
    mut port: u_short,
    mut ctype: *mut libc::c_char,
    mut rname: *mut libc::c_char,
    mut reason: *mut libc::c_int,
    mut errmsg: *mut *const libc::c_char,
) -> *mut Channel {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut pset: *mut permission_set = &mut (*sc).local_perms;
    let mut cctx: channel_connect = channel_connect {
        host: 0 as *mut libc::c_char,
        port: 0,
        ai: 0 as *mut addrinfo,
        aitop: 0 as *mut addrinfo,
    };
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut i: u_int = 0;
    let mut permit: u_int = 0;
    let mut permit_adm: u_int = 1 as libc::c_int as u_int;
    let mut sock: libc::c_int = 0;
    let mut perm: *mut permission = 0 as *mut permission;
    permit = (*pset).all_permitted as u_int;
    if permit == 0 {
        i = 0 as libc::c_int as u_int;
        while i < (*pset).num_permitted_user {
            perm = &mut *((*pset).permitted_user).offset(i as isize) as *mut permission;
            if open_match(perm, host, port as libc::c_int) != 0 {
                permit = 1 as libc::c_int as u_int;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
    }
    if (*pset).num_permitted_admin > 0 as libc::c_int as libc::c_uint {
        permit_adm = 0 as libc::c_int as u_int;
        i = 0 as libc::c_int as u_int;
        while i < (*pset).num_permitted_admin {
            perm = &mut *((*pset).permitted_admin).offset(i as isize) as *mut permission;
            if open_match(perm, host, port as libc::c_int) != 0 {
                permit_adm = 1 as libc::c_int as u_int;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
    }
    if permit == 0 || permit_adm == 0 {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<
                &[u8; 24],
                &[libc::c_char; 24],
            >(b"channel_connect_to_port\0"))
                .as_ptr(),
            4779 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Received request from %.100s port %d to connect to host %.100s port %d, but the request was denied.\0"
                as *const u8 as *const libc::c_char,
            ssh_remote_ipaddr(ssh),
            ssh_remote_port(ssh),
            host,
            port as libc::c_int,
        );
        if !reason.is_null() {
            *reason = 1 as libc::c_int;
        }
        return 0 as *mut Channel;
    }
    memset(
        &mut cctx as *mut channel_connect as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<channel_connect>() as libc::c_ulong,
    );
    sock = connect_to_helper(
        ssh,
        host,
        port as libc::c_int,
        SOCK_STREAM as libc::c_int,
        ctype,
        rname,
        &mut cctx,
        reason,
        errmsg,
    );
    if sock == -(1 as libc::c_int) {
        channel_connect_ctx_free(&mut cctx);
        return 0 as *mut Channel;
    }
    c = channel_new(
        ssh,
        ctype,
        12 as libc::c_int,
        sock,
        sock,
        -(1 as libc::c_int),
        (64 as libc::c_int * (32 as libc::c_int * 1024 as libc::c_int)) as u_int,
        (32 as libc::c_int * 1024 as libc::c_int) as u_int,
        0 as libc::c_int,
        rname,
        1 as libc::c_int,
    );
    (*c).host_port = port as libc::c_int;
    (*c).path = xstrdup(host);
    (*c).connect_ctx = cctx;
    return c;
}
pub unsafe extern "C" fn channel_connect_to_path(
    mut ssh: *mut ssh,
    mut path: *const libc::c_char,
    mut ctype: *mut libc::c_char,
    mut rname: *mut libc::c_char,
) -> *mut Channel {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut pset: *mut permission_set = &mut (*sc).local_perms;
    let mut i: u_int = 0;
    let mut permit: u_int = 0;
    let mut permit_adm: u_int = 1 as libc::c_int as u_int;
    let mut perm: *mut permission = 0 as *mut permission;
    permit = (*pset).all_permitted as u_int;
    if permit == 0 {
        i = 0 as libc::c_int as u_int;
        while i < (*pset).num_permitted_user {
            perm = &mut *((*pset).permitted_user).offset(i as isize) as *mut permission;
            if open_match(perm, path, -(2 as libc::c_int)) != 0 {
                permit = 1 as libc::c_int as u_int;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
    }
    if (*pset).num_permitted_admin > 0 as libc::c_int as libc::c_uint {
        permit_adm = 0 as libc::c_int as u_int;
        i = 0 as libc::c_int as u_int;
        while i < (*pset).num_permitted_admin {
            perm = &mut *((*pset).permitted_admin).offset(i as isize) as *mut permission;
            if open_match(perm, path, -(2 as libc::c_int)) != 0 {
                permit_adm = 1 as libc::c_int as u_int;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
    }
    if permit == 0 || permit_adm == 0 {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"channel_connect_to_path\0",
            ))
            .as_ptr(),
            4836 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Received request to connect to path %.100s, but the request was denied.\0"
                as *const u8 as *const libc::c_char,
            path,
        );
        return 0 as *mut Channel;
    }
    return connect_to(ssh, path, -(2 as libc::c_int), ctype, rname);
}
pub unsafe extern "C" fn channel_send_window_changes(mut ssh: *mut ssh) {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut ws: winsize = winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let mut r: libc::c_int = 0;
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < (*sc).channels_alloc {
        if !((*((*sc).channels).offset(i as isize)).is_null()
            || (**((*sc).channels).offset(i as isize)).client_tty == 0
            || (**((*sc).channels).offset(i as isize)).type_0 != 4 as libc::c_int)
        {
            if !(ioctl(
                (**((*sc).channels).offset(i as isize)).rfd,
                0x5413 as libc::c_int as libc::c_ulong,
                &mut ws as *mut winsize,
            ) == -(1 as libc::c_int))
            {
                channel_request_start(
                    ssh,
                    i as libc::c_int,
                    b"window-change\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                    0 as libc::c_int,
                );
                r = sshpkt_put_u32(ssh, ws.ws_col as u_int);
                if r != 0 as libc::c_int
                    || {
                        r = sshpkt_put_u32(ssh, ws.ws_row as u_int);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshpkt_put_u32(ssh, ws.ws_xpixel as u_int);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshpkt_put_u32(ssh, ws.ws_ypixel as u_int);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshpkt_send(ssh);
                        r != 0 as libc::c_int
                    }
                {
                    sshfatal(
                        b"channels.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                            b"channel_send_window_changes\0",
                        ))
                        .as_ptr(),
                        4862 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"channel %u; send window-change\0" as *const u8 as *const libc::c_char,
                        i,
                    );
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn rdynamic_connect_prepare(
    mut ssh: *mut ssh,
    mut ctype: *mut libc::c_char,
    mut rname: *mut libc::c_char,
) -> *mut Channel {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut r: libc::c_int = 0;
    c = channel_new(
        ssh,
        ctype,
        21 as libc::c_int,
        -(1 as libc::c_int),
        -(1 as libc::c_int),
        -(1 as libc::c_int),
        (64 as libc::c_int * (32 as libc::c_int * 1024 as libc::c_int)) as u_int,
        (32 as libc::c_int * 1024 as libc::c_int) as u_int,
        0 as libc::c_int,
        rname,
        1 as libc::c_int,
    );
    (*c).host_port = 0 as libc::c_int;
    (*c).path = 0 as *mut libc::c_char;
    r = sshpkt_start(ssh, 91 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_u32(ssh, (*c).remote_id);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, (*c).self_0 as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, (*c).local_window);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, (*c).local_maxpacket);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"rdynamic_connect_prepare\0",
            ))
            .as_ptr(),
            4887 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"channel %i; confirm\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
        );
    }
    return c;
}
unsafe extern "C" fn rdynamic_connect_finish(
    mut ssh: *mut ssh,
    mut c: *mut Channel,
) -> libc::c_int {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut pset: *mut permission_set = &mut (*sc).local_perms;
    let mut perm: *mut permission = 0 as *mut permission;
    let mut cctx: channel_connect = channel_connect {
        host: 0 as *mut libc::c_char,
        port: 0,
        ai: 0 as *mut addrinfo,
        aitop: 0 as *mut addrinfo,
    };
    let mut i: u_int = 0;
    let mut permit_adm: u_int = 1 as libc::c_int as u_int;
    let mut sock: libc::c_int = 0;
    if (*pset).num_permitted_admin > 0 as libc::c_int as libc::c_uint {
        permit_adm = 0 as libc::c_int as u_int;
        i = 0 as libc::c_int as u_int;
        while i < (*pset).num_permitted_admin {
            perm = &mut *((*pset).permitted_admin).offset(i as isize) as *mut permission;
            if open_match(perm, (*c).path, (*c).host_port) != 0 {
                permit_adm = 1 as libc::c_int as u_int;
                break;
            } else {
                i = i.wrapping_add(1);
                i;
            }
        }
    }
    if permit_adm == 0 {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"rdynamic_connect_finish\0",
            ))
            .as_ptr(),
            4913 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"requested forward not permitted\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    memset(
        &mut cctx as *mut channel_connect as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<channel_connect>() as libc::c_ulong,
    );
    sock = connect_to_helper(
        ssh,
        (*c).path,
        (*c).host_port,
        SOCK_STREAM as libc::c_int,
        0 as *mut libc::c_char,
        0 as *mut libc::c_char,
        &mut cctx,
        0 as *mut libc::c_int,
        0 as *mut *const libc::c_char,
    );
    if sock == -(1 as libc::c_int) {
        channel_connect_ctx_free(&mut cctx);
    } else {
        (*c).type_0 = 22 as libc::c_int;
        (*c).connect_ctx = cctx;
        channel_register_fds(
            ssh,
            c,
            sock,
            sock,
            -(1 as libc::c_int),
            0 as libc::c_int,
            1 as libc::c_int,
            0 as libc::c_int,
        );
    }
    return sock;
}
pub unsafe extern "C" fn x11_create_display_inet(
    mut ssh: *mut ssh,
    mut x11_display_offset: libc::c_int,
    mut x11_use_localhost: libc::c_int,
    mut single_connection: libc::c_int,
    mut display_numberp: *mut u_int,
    mut chanids: *mut *mut libc::c_int,
) -> libc::c_int {
    let mut nc: *mut Channel = 0 as *mut Channel;
    let mut display_number: libc::c_int = 0;
    let mut sock: libc::c_int = 0;
    let mut port: u_short = 0;
    let mut hints: addrinfo = addrinfo {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: 0 as *mut sockaddr,
        ai_canonname: 0 as *mut libc::c_char,
        ai_next: 0 as *mut addrinfo,
    };
    let mut ai: *mut addrinfo = 0 as *mut addrinfo;
    let mut aitop: *mut addrinfo = 0 as *mut addrinfo;
    let mut strport: [libc::c_char; 32] = [0; 32];
    let mut gaierr: libc::c_int = 0;
    let mut n: libc::c_int = 0;
    let mut num_socks: libc::c_int = 0 as libc::c_int;
    let mut socks: [libc::c_int; 10] = [0; 10];
    if chanids.is_null() {
        return -(1 as libc::c_int);
    }
    display_number = x11_display_offset;
    while display_number < 1000 as libc::c_int {
        port = (6000 as libc::c_int + display_number) as u_short;
        memset(
            &mut hints as *mut addrinfo as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
        );
        hints.ai_family = (*(*ssh).chanctxt).IPv4or6;
        hints.ai_flags = if x11_use_localhost != 0 {
            0 as libc::c_int
        } else {
            0x1 as libc::c_int
        };
        hints.ai_socktype = SOCK_STREAM as libc::c_int;
        snprintf(
            strport.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
            b"%d\0" as *const u8 as *const libc::c_char,
            port as libc::c_int,
        );
        gaierr = getaddrinfo(
            0 as *const libc::c_char,
            strport.as_mut_ptr(),
            &mut hints,
            &mut aitop,
        );
        if gaierr != 0 as libc::c_int {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"x11_create_display_inet\0",
                ))
                .as_ptr(),
                4964 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"getaddrinfo: %.100s\0" as *const u8 as *const libc::c_char,
                ssh_gai_strerror(gaierr),
            );
            return -(1 as libc::c_int);
        }
        ai = aitop;
        while !ai.is_null() {
            if !((*ai).ai_family != 2 as libc::c_int && (*ai).ai_family != 10 as libc::c_int) {
                sock = socket((*ai).ai_family, (*ai).ai_socktype, (*ai).ai_protocol);
                if sock == -(1 as libc::c_int) {
                    if *__errno_location() != 22 as libc::c_int
                        && *__errno_location() != 97 as libc::c_int
                        && *__errno_location() != 96 as libc::c_int
                    {
                        sshlog(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                                b"x11_create_display_inet\0",
                            ))
                            .as_ptr(),
                            4979 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"socket: %.100s\0" as *const u8 as *const libc::c_char,
                            strerror(*__errno_location()),
                        );
                        freeaddrinfo(aitop);
                        return -(1 as libc::c_int);
                    } else {
                        sshlog(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                                b"x11_create_display_inet\0",
                            ))
                            .as_ptr(),
                            4984 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"x11_create_display_inet: Socket family %d not supported\0"
                                as *const u8 as *const libc::c_char,
                            (*ai).ai_family,
                        );
                    }
                } else {
                    if (*ai).ai_family == 10 as libc::c_int {
                        sock_set_v6only(sock);
                    }
                    if x11_use_localhost != 0 {
                        set_reuseaddr(sock);
                    }
                    if bind(
                        sock,
                        __CONST_SOCKADDR_ARG {
                            __sockaddr__: (*ai).ai_addr,
                        },
                        (*ai).ai_addrlen,
                    ) == -(1 as libc::c_int)
                    {
                        sshlog(
                            b"channels.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                                b"x11_create_display_inet\0",
                            ))
                            .as_ptr(),
                            4994 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG2,
                            0 as *const libc::c_char,
                            b"bind port %d: %.100s\0" as *const u8 as *const libc::c_char,
                            port as libc::c_int,
                            strerror(*__errno_location()),
                        );
                        close(sock);
                        n = 0 as libc::c_int;
                        while n < num_socks {
                            close(socks[n as usize]);
                            n += 1;
                            n;
                        }
                        num_socks = 0 as libc::c_int;
                        break;
                    } else {
                        let fresh34 = num_socks;
                        num_socks = num_socks + 1;
                        socks[fresh34 as usize] = sock;
                        if num_socks == 10 as libc::c_int {
                            break;
                        }
                    }
                }
            }
            ai = (*ai).ai_next;
        }
        freeaddrinfo(aitop);
        if num_socks > 0 as libc::c_int {
            break;
        }
        display_number += 1;
        display_number;
    }
    if display_number >= 1000 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"x11_create_display_inet\0",
            ))
            .as_ptr(),
            5010 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Failed to allocate internet-domain X11 display socket.\0" as *const u8
                as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    n = 0 as libc::c_int;
    while n < num_socks {
        sock = socks[n as usize];
        if listen(sock, 128 as libc::c_int) == -(1 as libc::c_int) {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"x11_create_display_inet\0",
                ))
                .as_ptr(),
                5017 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"listen: %.100s\0" as *const u8 as *const libc::c_char,
                strerror(*__errno_location()),
            );
            close(sock);
            return -(1 as libc::c_int);
        }
        n += 1;
        n;
    }
    *chanids = xcalloc(
        (num_socks + 1 as libc::c_int) as size_t,
        ::core::mem::size_of::<libc::c_int>() as libc::c_ulong,
    ) as *mut libc::c_int;
    n = 0 as libc::c_int;
    while n < num_socks {
        sock = socks[n as usize];
        nc = channel_new(
            ssh,
            b"x11-listener\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            1 as libc::c_int,
            sock,
            sock,
            -(1 as libc::c_int),
            (4 as libc::c_int * (16 as libc::c_int * 1024 as libc::c_int)) as u_int,
            (16 as libc::c_int * 1024 as libc::c_int) as u_int,
            0 as libc::c_int,
            b"X11 inet listener\0" as *const u8 as *const libc::c_char,
            1 as libc::c_int,
        );
        (*nc).single_connection = single_connection;
        *(*chanids).offset(n as isize) = (*nc).self_0;
        n += 1;
        n;
    }
    *(*chanids).offset(n as isize) = -(1 as libc::c_int);
    *display_numberp = display_number as u_int;
    return 0 as libc::c_int;
}
unsafe extern "C" fn connect_local_xsocket_path(mut pathname: *const libc::c_char) -> libc::c_int {
    let mut sock: libc::c_int = 0;
    let mut addr: sockaddr_un = sockaddr_un {
        sun_family: 0,
        sun_path: [0; 108],
    };
    sock = socket(
        1 as libc::c_int,
        SOCK_STREAM as libc::c_int,
        0 as libc::c_int,
    );
    if sock == -(1 as libc::c_int) {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"connect_local_xsocket_path\0",
            ))
            .as_ptr(),
            5049 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"socket: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    memset(
        &mut addr as *mut sockaddr_un as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_un>() as libc::c_ulong,
    );
    addr.sun_family = 1 as libc::c_int as sa_family_t;
    strlcpy(
        (addr.sun_path).as_mut_ptr(),
        pathname,
        ::core::mem::size_of::<[libc::c_char; 108]>() as libc::c_ulong,
    );
    if connect(
        sock,
        __CONST_SOCKADDR_ARG {
            __sockaddr__: &mut addr as *mut sockaddr_un as *mut sockaddr,
        },
        ::core::mem::size_of::<sockaddr_un>() as libc::c_ulong as socklen_t,
    ) == 0 as libc::c_int
    {
        return sock;
    }
    close(sock);
    sshlog(
        b"channels.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
            b"connect_local_xsocket_path\0",
        ))
        .as_ptr(),
        5058 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"connect %.100s: %.100s\0" as *const u8 as *const libc::c_char,
        (addr.sun_path).as_mut_ptr(),
        strerror(*__errno_location()),
    );
    return -(1 as libc::c_int);
}
unsafe extern "C" fn connect_local_xsocket(mut dnr: u_int) -> libc::c_int {
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    snprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        b"/tmp/.X11-unix/X%u\0" as *const u8 as *const libc::c_char,
        dnr,
    );
    return connect_local_xsocket_path(buf.as_mut_ptr());
}
pub unsafe extern "C" fn x11_connect_display(mut ssh: *mut ssh) -> libc::c_int {
    let mut display_number: u_int = 0;
    let mut display: *const libc::c_char = 0 as *const libc::c_char;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hints: addrinfo = addrinfo {
        ai_flags: 0,
        ai_family: 0,
        ai_socktype: 0,
        ai_protocol: 0,
        ai_addrlen: 0,
        ai_addr: 0 as *mut sockaddr,
        ai_canonname: 0 as *mut libc::c_char,
        ai_next: 0 as *mut addrinfo,
    };
    let mut ai: *mut addrinfo = 0 as *mut addrinfo;
    let mut aitop: *mut addrinfo = 0 as *mut addrinfo;
    let mut strport: [libc::c_char; 32] = [0; 32];
    let mut gaierr: libc::c_int = 0;
    let mut sock: libc::c_int = 0 as libc::c_int;
    display = getenv(b"DISPLAY\0" as *const u8 as *const libc::c_char);
    if display.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"x11_connect_display\0"))
                .as_ptr(),
            5110 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"DISPLAY not set.\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if strncmp(
        display,
        b"unix:\0" as *const u8 as *const libc::c_char,
        5 as libc::c_int as libc::c_ulong,
    ) == 0 as libc::c_int
        || *display.offset(0 as libc::c_int as isize) as libc::c_int == ':' as i32
    {
        if sscanf(
            (strrchr(display, ':' as i32)).offset(1 as libc::c_int as isize),
            b"%u\0" as *const u8 as *const libc::c_char,
            &mut display_number as *mut u_int,
        ) != 1 as libc::c_int
        {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"x11_connect_display\0",
                ))
                .as_ptr(),
                5146 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Could not parse display number from DISPLAY: %.100s\0" as *const u8
                    as *const libc::c_char,
                display,
            );
            return -(1 as libc::c_int);
        }
        sock = connect_local_xsocket(display_number);
        if sock < 0 as libc::c_int {
            return -(1 as libc::c_int);
        }
        return sock;
    }
    strlcpy(
        buf.as_mut_ptr(),
        display,
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
    );
    cp = strchr(buf.as_mut_ptr(), ':' as i32);
    if cp.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"x11_connect_display\0"))
                .as_ptr(),
            5164 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Could not find ':' in DISPLAY: %.100s\0" as *const u8 as *const libc::c_char,
            display,
        );
        return -(1 as libc::c_int);
    }
    *cp = 0 as libc::c_int as libc::c_char;
    if sscanf(
        cp.offset(1 as libc::c_int as isize),
        b"%u\0" as *const u8 as *const libc::c_char,
        &mut display_number as *mut u_int,
    ) != 1 as libc::c_int
    {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"x11_connect_display\0"))
                .as_ptr(),
            5174 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Could not parse display number from DISPLAY: %.100s\0" as *const u8
                as *const libc::c_char,
            display,
        );
        return -(1 as libc::c_int);
    }
    memset(
        &mut hints as *mut addrinfo as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
    );
    hints.ai_family = (*(*ssh).chanctxt).IPv4or6;
    hints.ai_socktype = SOCK_STREAM as libc::c_int;
    snprintf(
        strport.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
        b"%u\0" as *const u8 as *const libc::c_char,
        (6000 as libc::c_int as libc::c_uint).wrapping_add(display_number),
    );
    gaierr = getaddrinfo(
        buf.as_mut_ptr(),
        strport.as_mut_ptr(),
        &mut hints,
        &mut aitop,
    );
    if gaierr != 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"x11_connect_display\0"))
                .as_ptr(),
            5185 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%.100s: unknown host. (%s)\0" as *const u8 as *const libc::c_char,
            buf.as_mut_ptr(),
            ssh_gai_strerror(gaierr),
        );
        return -(1 as libc::c_int);
    }
    ai = aitop;
    while !ai.is_null() {
        sock = socket((*ai).ai_family, (*ai).ai_socktype, (*ai).ai_protocol);
        if sock == -(1 as libc::c_int) {
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"x11_connect_display\0",
                ))
                .as_ptr(),
                5192 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"socket: %.100s\0" as *const u8 as *const libc::c_char,
                strerror(*__errno_location()),
            );
        } else {
            if !(connect(
                sock,
                __CONST_SOCKADDR_ARG {
                    __sockaddr__: (*ai).ai_addr,
                },
                (*ai).ai_addrlen,
            ) == -(1 as libc::c_int))
            {
                break;
            }
            sshlog(
                b"channels.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"x11_connect_display\0",
                ))
                .as_ptr(),
                5198 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"connect %.100s port %u: %.100s\0" as *const u8 as *const libc::c_char,
                buf.as_mut_ptr(),
                (6000 as libc::c_int as libc::c_uint).wrapping_add(display_number),
                strerror(*__errno_location()),
            );
            close(sock);
        }
        ai = (*ai).ai_next;
    }
    freeaddrinfo(aitop);
    if ai.is_null() {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"x11_connect_display\0"))
                .as_ptr(),
            5208 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"connect %.100s port %u: %.100s\0" as *const u8 as *const libc::c_char,
            buf.as_mut_ptr(),
            (6000 as libc::c_int as libc::c_uint).wrapping_add(display_number),
            strerror(*__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    set_nodelay(sock);
    return sock;
}
pub unsafe extern "C" fn x11_request_forwarding_with_spoofing(
    mut ssh: *mut ssh,
    mut client_session_id: libc::c_int,
    mut disp: *const libc::c_char,
    mut proto: *const libc::c_char,
    mut data: *const libc::c_char,
    mut want_reply: libc::c_int,
) {
    let mut sc: *mut ssh_channels = (*ssh).chanctxt;
    let mut data_len: u_int =
        (strlen(data) as u_int).wrapping_div(2 as libc::c_int as libc::c_uint);
    let mut i: u_int = 0;
    let mut value: u_int = 0;
    let mut cp: *const libc::c_char = 0 as *const libc::c_char;
    let mut new_data: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut screen_number: libc::c_int = 0;
    if ((*sc).x11_saved_display).is_null() {
        (*sc).x11_saved_display = xstrdup(disp);
    } else if strcmp(disp, (*sc).x11_saved_display) != 0 as libc::c_int {
        sshlog(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                b"x11_request_forwarding_with_spoofing\0",
            ))
            .as_ptr(),
            5235 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"x11_request_forwarding_with_spoofing: different $DISPLAY already forwarded\0"
                as *const u8 as *const libc::c_char,
        );
        return;
    }
    cp = strchr(disp, ':' as i32);
    if !cp.is_null() {
        cp = strchr(cp, '.' as i32);
    }
    if !cp.is_null() {
        screen_number = strtonum(
            cp.offset(1 as libc::c_int as isize),
            0 as libc::c_int as libc::c_longlong,
            400 as libc::c_int as libc::c_longlong,
            0 as *mut *const libc::c_char,
        ) as u_int as libc::c_int;
    } else {
        screen_number = 0 as libc::c_int;
    }
    if ((*sc).x11_saved_proto).is_null() {
        (*sc).x11_saved_proto = xstrdup(proto);
        (*sc).x11_saved_data = xmalloc(data_len as size_t) as *mut libc::c_char;
        i = 0 as libc::c_int as u_int;
        while i < data_len {
            if sscanf(
                data.offset((2 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
                b"%2x\0" as *const u8 as *const libc::c_char,
                &mut value as *mut u_int,
            ) != 1 as libc::c_int
            {
                sshfatal(
                    b"channels.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                        b"x11_request_forwarding_with_spoofing\0",
                    ))
                    .as_ptr(),
                    5256 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"x11_request_forwarding: bad authentication data: %.100s\0" as *const u8
                        as *const libc::c_char,
                    data,
                );
            }
            *((*sc).x11_saved_data).offset(i as isize) = value as libc::c_char;
            i = i.wrapping_add(1);
            i;
        }
        (*sc).x11_saved_data_len = data_len;
        (*sc).x11_fake_data = xmalloc(data_len as size_t) as *mut u_char;
        arc4random_buf((*sc).x11_fake_data as *mut libc::c_void, data_len as size_t);
        (*sc).x11_fake_data_len = data_len;
    }
    new_data = tohex(
        (*sc).x11_fake_data as *const libc::c_void,
        data_len as size_t,
    );
    channel_request_start(
        ssh,
        client_session_id,
        b"x11-req\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        want_reply,
    );
    r = sshpkt_put_u8(ssh, 0 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_cstring(ssh, proto as *const libc::c_void);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_cstring(ssh, new_data as *const libc::c_void);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, screen_number as u_int32_t);
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
        sshfatal(
            b"channels.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                b"x11_request_forwarding_with_spoofing\0",
            ))
            .as_ptr(),
            5279 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send x11-req\0" as *const u8 as *const libc::c_char,
        );
    }
    free(new_data as *mut libc::c_void);
}
