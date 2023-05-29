use crate::kex::dh_st;
use crate::packet::key_entry;

use crate::packet::ssh;

use crate::atomicio::atomicio;

use ::libc;
use libc::close;
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
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;

    pub type ec_group_st;

    static mut stdout: *mut libc::FILE;
    static mut stderr: *mut libc::FILE;
    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;

    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::FILE;

    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;

    fn fgets(
        __s: *mut libc::c_char,
        __n: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> *mut libc::c_char;
    fn __getdelim(
        __lineptr: *mut *mut libc::c_char,
        __n: *mut size_t,
        __delimiter: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> __ssize_t;
    fn fputs(__s: *const libc::c_char, __stream: *mut libc::FILE) -> libc::c_int;

    fn pclose(__stream: *mut libc::FILE) -> libc::c_int;
    fn popen(__command: *const libc::c_char, __modes: *const libc::c_char) -> *mut libc::FILE;
    fn getpeername(__fd: libc::c_int, __addr: __SOCKADDR_ARG, __len: *mut socklen_t)
        -> libc::c_int;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn tcsendbreak(__fd: libc::c_int, __duration: libc::c_int) -> libc::c_int;

    fn endpwent();
    fn platform_privileged_uidswap() -> libc::c_int;
    fn platform_setusercontext(_: *mut libc::passwd);
    fn platform_setusercontext_post_groups(_: *mut libc::passwd);
    fn killpg(__pgrp: __pid_t, __sig: libc::c_int) -> libc::c_int;

    fn closefrom(__lowfd: libc::c_int);
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn pipe(__pipedes: *mut libc::c_int) -> libc::c_int;
    fn chdir(__path: *const libc::c_char) -> libc::c_int;
    fn dup(__fd: libc::c_int) -> libc::c_int;

    static mut environ: *mut *mut libc::c_char;
    fn execve(
        __path: *const libc::c_char,
        __argv: *const *mut libc::c_char,
        __envp: *const *mut libc::c_char,
    ) -> libc::c_int;
    fn execl(__path: *const libc::c_char, __arg: *const libc::c_char, _: ...) -> libc::c_int;

    fn setsid() -> __pid_t;

    fn geteuid() -> __uid_t;
    fn setgid(__gid: __gid_t) -> libc::c_int;

    fn unlink(__name: *const libc::c_char) -> libc::c_int;
    fn rmdir(__path: *const libc::c_char) -> libc::c_int;
    fn setlogin(__name: *const libc::c_char) -> libc::c_int;
    static mut BSDoptind: libc::c_int;
    fn gethostname(__name: *mut libc::c_char, __len: size_t) -> libc::c_int;
    fn chroot(__path: *const libc::c_char) -> libc::c_int;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn _ssh_mkstemp(_: *mut libc::c_char) -> libc::c_int;
    fn setproctitle(fmt: *const libc::c_char, _: ...);
    static mut BSDoptreset: libc::c_int;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;

    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;

    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strtok(_: *mut libc::c_char, _: *const libc::c_char) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    fn endgrent();
    fn initgroups(__user: *const libc::c_char, __group: __gid_t) -> libc::c_int;

    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn mkdtemp(__template: *mut libc::c_char) -> *mut libc::c_char;

    fn pty_allocate(
        _: *mut libc::c_int,
        _: *mut libc::c_int,
        _: *mut libc::c_char,
        _: size_t,
    ) -> libc::c_int;
    fn pty_release(_: *const libc::c_char);
    fn pty_make_controlling_tty(_: *mut libc::c_int, _: *const libc::c_char);
    fn pty_change_window_size(_: libc::c_int, _: u_int, _: u_int, _: u_int, _: u_int);
    fn pty_setowner(_: *mut libc::passwd, _: *const libc::c_char);
    fn sshpkt_fmt_connection_id(ssh: *mut ssh, s: *mut libc::c_char, l: size_t);

    fn sshpkt_fatal(ssh: *mut ssh, r: libc::c_int, fmt: *const libc::c_char, _: ...) -> !;

    fn ssh_local_port(_: *mut ssh) -> libc::c_int;
    fn ssh_remote_port(_: *mut ssh) -> libc::c_int;
    fn ssh_remote_ipaddr(_: *mut ssh) -> *const libc::c_char;
    fn ssh_tty_parse_modes(_: *mut ssh, _: libc::c_int);
    fn ssh_packet_connection_is_on_socket(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_send_debug(_: *mut ssh, fmt: *const libc::c_char, _: ...);

    fn ssh_packet_set_interactive(_: *mut ssh, _: libc::c_int, _: libc::c_int, _: libc::c_int);
    fn ssh_packet_clear_keys(_: *mut ssh);
    fn ssh_packet_get_connection_out(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_get_connection_in(_: *mut ssh) -> libc::c_int;

    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn match_pattern(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn match_pattern_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn temporarily_use_uid(_: *mut libc::passwd);
    fn restore_uid();
    fn permanently_set_uid(_: *mut libc::passwd);
    fn channel_by_id(_: *mut ssh, _: libc::c_int) -> *mut Channel;
    fn channel_lookup(_: *mut ssh, _: libc::c_int) -> *mut Channel;
    fn channel_new(
        _: *mut ssh,
        _: *mut libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: u_int,
        _: u_int,
        _: libc::c_int,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> *mut Channel;
    fn channel_set_fds(
        _: *mut ssh,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: u_int,
    );
    fn channel_set_xtype(_: *mut ssh, _: libc::c_int, _: *const libc::c_char);
    fn channel_request_start(_: *mut ssh, _: libc::c_int, _: *mut libc::c_char, _: libc::c_int);
    fn channel_register_cleanup(
        _: *mut ssh,
        _: libc::c_int,
        _: Option<channel_callback_fn>,
        _: libc::c_int,
    );
    fn channel_cancel_cleanup(_: *mut ssh, _: libc::c_int);
    fn channel_close_all(_: *mut ssh);
    fn channel_permit_all(_: *mut ssh, _: libc::c_int);
    fn channel_add_permission(
        _: *mut ssh,
        _: libc::c_int,
        _: libc::c_int,
        _: *mut libc::c_char,
        _: libc::c_int,
    );
    fn channel_clear_permission(_: *mut ssh, _: libc::c_int, _: libc::c_int);
    fn channel_disable_admin(_: *mut ssh, _: libc::c_int);
    fn permitopen_port(_: *const libc::c_char) -> libc::c_int;
    fn x11_create_display_inet(
        _: *mut ssh,
        _: libc::c_int,
        _: libc::c_int,
        _: libc::c_int,
        _: *mut u_int,
        _: *mut *mut libc::c_int,
    ) -> libc::c_int;
    fn chan_mark_dead(_: *mut ssh, _: *mut Channel);
    fn chan_write_failed(_: *mut ssh, _: *mut Channel);
    fn auth_get_canonical_hostname(_: *mut ssh, _: libc::c_int) -> *const libc::c_char;
    fn auth_log_authopts(_: *const libc::c_char, _: *const sshauthopt, _: libc::c_int);
    fn auth_debug_send(_: *mut ssh);
    fn log_redirect_stderr_to(_: *const libc::c_char);
    fn cleanup_exit(_: libc::c_int) -> !;

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
    fn hpdelim2(_: *mut *mut libc::c_char, _: *mut libc::c_char) -> *mut libc::c_char;
    fn hpdelim(_: *mut *mut libc::c_char) -> *mut libc::c_char;
    fn cleanhostname(_: *mut libc::c_char) -> *mut libc::c_char;
    fn tilde_expand_filename(_: *const libc::c_char, _: uid_t) -> *mut libc::c_char;
    fn percent_expand(_: *const libc::c_char, _: ...) -> *mut libc::c_char;
    fn unix_listener(_: *const libc::c_char, _: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn path_absolute(_: *const libc::c_char) -> libc::c_int;
    fn child_set_env(
        envp: *mut *mut *mut libc::c_char,
        envsizep: *mut u_int,
        name: *const libc::c_char,
        value: *const libc::c_char,
    );

    fn record_login(
        _: pid_t,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: uid_t,
        _: *const libc::c_char,
        _: *mut sockaddr,
        _: socklen_t,
    );
    fn record_logout(_: pid_t, _: *const libc::c_char, _: *const libc::c_char);
    fn server_loop2(_: *mut ssh, _: *mut Authctxt);
    fn get_local_ipaddr(_: libc::c_int) -> *mut libc::c_char;
    static mut use_privsep: libc::c_int;
    fn mm_is_monitor() -> libc::c_int;
    fn mm_pty_allocate(
        _: *mut libc::c_int,
        _: *mut libc::c_int,
        _: *mut libc::c_char,
        _: size_t,
    ) -> libc::c_int;
    fn mm_session_pty_cleanup2(_: *mut Session);
    fn sftp_server_main(
        _: libc::c_int,
        _: *mut *mut libc::c_char,
        _: *mut libc::passwd,
    ) -> libc::c_int;

    static mut options: ServerOptions;
    static mut __progname: *mut libc::c_char;
    static mut debug_flag: libc::c_int;
    static mut utmp_len: u_int;
    fn destroy_sensitive_data();
    static mut loginmsg: *mut crate::sshbuf::sshbuf;
    static mut auth_opts: *mut sshauthopt;
    static mut tun_fwd_ifnames: *mut libc::c_char;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
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
pub type __pid_t = libc::c_int;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type uid_t = __uid_t;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;

pub type socklen_t = __socklen_t;
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
pub type uint64_t = __uint64_t;

pub type _IO_lock_t = ();

pub type sig_atomic_t = __sig_atomic_t;
pub type __sighandler_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
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
pub struct C2RustUnnamed_0 {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
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

pub type DH = dh_st;

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
pub type C2RustUnnamed_4 = libc::c_uint;
pub const _ISalnum: C2RustUnnamed_4 = 8;
pub const _ISpunct: C2RustUnnamed_4 = 4;
pub const _IScntrl: C2RustUnnamed_4 = 2;
pub const _ISblank: C2RustUnnamed_4 = 1;
pub const _ISgraph: C2RustUnnamed_4 = 32768;
pub const _ISprint: C2RustUnnamed_4 = 16384;
pub const _ISspace: C2RustUnnamed_4 = 8192;
pub const _ISxdigit: C2RustUnnamed_4 = 4096;
pub const _ISdigit: C2RustUnnamed_4 = 2048;
pub const _ISalpha: C2RustUnnamed_4 = 1024;
pub const _ISlower: C2RustUnnamed_4 = 512;
pub const _ISupper: C2RustUnnamed_4 = 256;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ForwardOptions {
    pub gateway_ports: libc::c_int,
    pub streamlocal_bind_mask: mode_t,
    pub streamlocal_bind_unlink: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshauthopt {
    pub permit_port_forwarding_flag: libc::c_int,
    pub permit_agent_forwarding_flag: libc::c_int,
    pub permit_x11_forwarding_flag: libc::c_int,
    pub permit_pty_flag: libc::c_int,
    pub permit_user_rc: libc::c_int,
    pub restricted: libc::c_int,
    pub valid_before: uint64_t,
    pub cert_authority: libc::c_int,
    pub cert_principals: *mut libc::c_char,
    pub force_tun_device: libc::c_int,
    pub force_command: *mut libc::c_char,
    pub nenv: size_t,
    pub env: *mut *mut libc::c_char,
    pub npermitopen: size_t,
    pub permitopen: *mut *mut libc::c_char,
    pub npermitlisten: size_t,
    pub permitlisten: *mut *mut libc::c_char,
    pub required_from_host_cert: *mut libc::c_char,
    pub required_from_host_keys: *mut libc::c_char,
    pub no_require_user_presence: libc::c_int,
    pub require_verify: libc::c_int,
}
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
pub struct queued_listenaddr {
    pub addr: *mut libc::c_char,
    pub port: libc::c_int,
    pub rdomain: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct listenaddr {
    pub rdomain: *mut libc::c_char,
    pub addrs: *mut addrinfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ServerOptions {
    pub num_ports: u_int,
    pub ports_from_cmdline: u_int,
    pub ports: [libc::c_int; 256],
    pub queued_listen_addrs: *mut queued_listenaddr,
    pub num_queued_listens: u_int,
    pub listen_addrs: *mut listenaddr,
    pub num_listen_addrs: u_int,
    pub address_family: libc::c_int,
    pub routing_domain: *mut libc::c_char,
    pub host_key_files: *mut *mut libc::c_char,
    pub host_key_file_userprovided: *mut libc::c_int,
    pub num_host_key_files: u_int,
    pub host_cert_files: *mut *mut libc::c_char,
    pub num_host_cert_files: u_int,
    pub host_key_agent: *mut libc::c_char,
    pub pid_file: *mut libc::c_char,
    pub moduli_file: *mut libc::c_char,
    pub login_grace_time: libc::c_int,
    pub permit_root_login: libc::c_int,
    pub ignore_rhosts: libc::c_int,
    pub ignore_user_known_hosts: libc::c_int,
    pub print_motd: libc::c_int,
    pub print_lastlog: libc::c_int,
    pub x11_forwarding: libc::c_int,
    pub x11_display_offset: libc::c_int,
    pub x11_use_localhost: libc::c_int,
    pub xauth_location: *mut libc::c_char,
    pub permit_tty: libc::c_int,
    pub permit_user_rc: libc::c_int,
    pub strict_modes: libc::c_int,
    pub tcp_keep_alive: libc::c_int,
    pub ip_qos_interactive: libc::c_int,
    pub ip_qos_bulk: libc::c_int,
    pub ciphers: *mut libc::c_char,
    pub macs: *mut libc::c_char,
    pub kex_algorithms: *mut libc::c_char,
    pub fwd_opts: ForwardOptions,
    pub log_facility: SyslogFacility,
    pub log_level: LogLevel,
    pub num_log_verbose: u_int,
    pub log_verbose: *mut *mut libc::c_char,
    pub hostbased_authentication: libc::c_int,
    pub hostbased_uses_name_from_packet_only: libc::c_int,
    pub hostbased_accepted_algos: *mut libc::c_char,
    pub hostkeyalgorithms: *mut libc::c_char,
    pub ca_sign_algorithms: *mut libc::c_char,
    pub pubkey_authentication: libc::c_int,
    pub pubkey_accepted_algos: *mut libc::c_char,
    pub pubkey_auth_options: libc::c_int,
    pub kerberos_authentication: libc::c_int,
    pub kerberos_or_local_passwd: libc::c_int,
    pub kerberos_ticket_cleanup: libc::c_int,
    pub kerberos_get_afs_token: libc::c_int,
    pub gss_authentication: libc::c_int,
    pub gss_cleanup_creds: libc::c_int,
    pub gss_strict_acceptor: libc::c_int,
    pub password_authentication: libc::c_int,
    pub kbd_interactive_authentication: libc::c_int,
    pub permit_empty_passwd: libc::c_int,
    pub permit_user_env: libc::c_int,
    pub permit_user_env_allowlist: *mut libc::c_char,
    pub compression: libc::c_int,
    pub allow_tcp_forwarding: libc::c_int,
    pub allow_streamlocal_forwarding: libc::c_int,
    pub allow_agent_forwarding: libc::c_int,
    pub disable_forwarding: libc::c_int,
    pub num_allow_users: u_int,
    pub allow_users: *mut *mut libc::c_char,
    pub num_deny_users: u_int,
    pub deny_users: *mut *mut libc::c_char,
    pub num_allow_groups: u_int,
    pub allow_groups: *mut *mut libc::c_char,
    pub num_deny_groups: u_int,
    pub deny_groups: *mut *mut libc::c_char,
    pub num_subsystems: u_int,
    pub subsystem_name: [*mut libc::c_char; 256],
    pub subsystem_command: [*mut libc::c_char; 256],
    pub subsystem_args: [*mut libc::c_char; 256],
    pub num_accept_env: u_int,
    pub accept_env: *mut *mut libc::c_char,
    pub num_setenv: u_int,
    pub setenv: *mut *mut libc::c_char,
    pub max_startups_begin: libc::c_int,
    pub max_startups_rate: libc::c_int,
    pub max_startups: libc::c_int,
    pub per_source_max_startups: libc::c_int,
    pub per_source_masklen_ipv4: libc::c_int,
    pub per_source_masklen_ipv6: libc::c_int,
    pub max_authtries: libc::c_int,
    pub max_sessions: libc::c_int,
    pub banner: *mut libc::c_char,
    pub use_dns: libc::c_int,
    pub client_alive_interval: libc::c_int,
    pub client_alive_count_max: libc::c_int,
    pub num_authkeys_files: u_int,
    pub authorized_keys_files: *mut *mut libc::c_char,
    pub adm_forced_command: *mut libc::c_char,
    pub use_pam: libc::c_int,
    pub permit_tun: libc::c_int,
    pub permitted_opens: *mut *mut libc::c_char,
    pub num_permitted_opens: u_int,
    pub permitted_listens: *mut *mut libc::c_char,
    pub num_permitted_listens: u_int,
    pub chroot_directory: *mut libc::c_char,
    pub revoked_keys_file: *mut libc::c_char,
    pub trusted_user_ca_keys: *mut libc::c_char,
    pub authorized_keys_command: *mut libc::c_char,
    pub authorized_keys_command_user: *mut libc::c_char,
    pub authorized_principals_file: *mut libc::c_char,
    pub authorized_principals_command: *mut libc::c_char,
    pub authorized_principals_command_user: *mut libc::c_char,
    pub rekey_limit: int64_t,
    pub rekey_interval: libc::c_int,
    pub version_addendum: *mut libc::c_char,
    pub num_auth_methods: u_int,
    pub auth_methods: *mut *mut libc::c_char,
    pub fingerprint_hash: libc::c_int,
    pub expose_userauth_info: libc::c_int,
    pub timing_secret: u_int64_t,
    pub sk_provider: *mut libc::c_char,
    pub required_rsa_size: libc::c_int,
    pub channel_timeouts: *mut *mut libc::c_char,
    pub num_channel_timeouts: u_int,
    pub unused_connection_timeout: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct Session {
    pub used: libc::c_int,
    pub self_0: libc::c_int,
    pub next_unused: libc::c_int,
    pub pw: *mut libc::passwd,
    pub authctxt: *mut Authctxt,
    pub pid: pid_t,
    pub forced: libc::c_int,
    pub term: *mut libc::c_char,
    pub ptyfd: libc::c_int,
    pub ttyfd: libc::c_int,
    pub ptymaster: libc::c_int,
    pub row: u_int,
    pub col: u_int,
    pub xpixel: u_int,
    pub ypixel: u_int,
    pub tty: [libc::c_char; 64],
    pub display_number: u_int,
    pub display: *mut libc::c_char,
    pub screen: u_int,
    pub auth_display: *mut libc::c_char,
    pub auth_proto: *mut libc::c_char,
    pub auth_data: *mut libc::c_char,
    pub single_connection: libc::c_int,
    pub chanid: libc::c_int,
    pub x11_chanids: *mut libc::c_int,
    pub is_subsystem: libc::c_int,
    pub subsys: *mut libc::c_char,
    pub num_env: u_int,
    pub env: *mut C2RustUnnamed_5,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_5 {
    pub name: *mut libc::c_char,
    pub val: *mut libc::c_char,
}
#[inline]
unsafe extern "C" fn getline(
    mut __lineptr: *mut *mut libc::c_char,
    mut __n: *mut size_t,
    mut __stream: *mut libc::FILE,
) -> __ssize_t {
    return __getdelim(__lineptr, __n, '\n' as i32, __stream);
}
pub static mut original_command: *const libc::c_char = 0 as *const libc::c_char;
static mut sessions_first_unused: libc::c_int = -(1 as libc::c_int);
static mut sessions_nalloc: libc::c_int = 0 as libc::c_int;
static mut sessions: *mut Session = 0 as *const Session as *mut Session;
static mut is_child: libc::c_int = 0 as libc::c_int;
static mut in_chroot: libc::c_int = 0 as libc::c_int;
static mut auth_info_file: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut auth_sock_name: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
static mut auth_sock_dir: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
unsafe extern "C" fn auth_sock_cleanup_proc(mut pw: *mut libc::passwd) {
    if !auth_sock_name.is_null() {
        temporarily_use_uid(pw);
        unlink(auth_sock_name);
        rmdir(auth_sock_dir);
        auth_sock_name = 0 as *mut libc::c_char;
        restore_uid();
    }
}
unsafe extern "C" fn auth_input_request_forwarding(
    mut ssh: *mut ssh,
    mut pw: *mut libc::passwd,
) -> libc::c_int {
    let mut nc: *mut Channel = 0 as *mut Channel;
    let mut sock: libc::c_int = -(1 as libc::c_int);
    if !auth_sock_name.is_null() {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"auth_input_request_forwarding\0",
            ))
            .as_ptr(),
            190 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"authentication forwarding requested twice.\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    temporarily_use_uid(pw);
    auth_sock_dir =
        crate::xmalloc::xstrdup(b"/tmp/ssh-XXXXXXXXXX\0" as *const u8 as *const libc::c_char);
    if (mkdtemp(auth_sock_dir)).is_null() {
        ssh_packet_send_debug(
            ssh,
            b"Agent forwarding disabled: mkdtemp() failed: %.100s\0" as *const u8
                as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        restore_uid();
        libc::free(auth_sock_dir as *mut libc::c_void);
        auth_sock_dir = 0 as *mut libc::c_char;
    } else {
        crate::xmalloc::xasprintf(
            &mut auth_sock_name as *mut *mut libc::c_char,
            b"%s/agent.%ld\0" as *const u8 as *const libc::c_char,
            auth_sock_dir,
            libc::getpid() as libc::c_long,
        );
        sock = unix_listener(auth_sock_name, 128 as libc::c_int, 0 as libc::c_int);
        restore_uid();
        if !(sock < 0 as libc::c_int) {
            nc = channel_new(
                ssh,
                b"auth-listener\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                6 as libc::c_int,
                sock,
                sock,
                -(1 as libc::c_int),
                (4 as libc::c_int * (16 as libc::c_int * 1024 as libc::c_int)) as u_int,
                (16 as libc::c_int * 1024 as libc::c_int) as u_int,
                0 as libc::c_int,
                b"auth socket\0" as *const u8 as *const libc::c_char,
                1 as libc::c_int,
            );
            (*nc).path = crate::xmalloc::xstrdup(auth_sock_name);
            return 1 as libc::c_int;
        }
    }
    libc::free(auth_sock_name as *mut libc::c_void);
    if !auth_sock_dir.is_null() {
        temporarily_use_uid(pw);
        rmdir(auth_sock_dir);
        restore_uid();
        libc::free(auth_sock_dir as *mut libc::c_void);
    }
    if sock != -(1 as libc::c_int) {
        close(sock);
    }
    auth_sock_name = 0 as *mut libc::c_char;
    auth_sock_dir = 0 as *mut libc::c_char;
    return 0 as libc::c_int;
}
unsafe extern "C" fn display_loginmsg() {
    let mut r: libc::c_int = 0;
    if crate::sshbuf::sshbuf_len(loginmsg) == 0 as libc::c_int as libc::c_ulong {
        return;
    }
    r = crate::sshbuf_getput_basic::sshbuf_put_u8(loginmsg, 0 as libc::c_int as u_char);
    if r != 0 as libc::c_int {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"display_loginmsg\0"))
                .as_ptr(),
            254 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"crate::sshbuf_getput_basic::sshbuf_put_u8\0" as *const u8 as *const libc::c_char,
        );
    }
    printf(
        b"%s\0" as *const u8 as *const libc::c_char,
        crate::sshbuf::sshbuf_ptr(loginmsg) as *mut libc::c_char,
    );
    crate::sshbuf::sshbuf_reset(loginmsg);
}
unsafe extern "C" fn prepare_auth_info_file(
    mut pw: *mut libc::passwd,
    mut info: *mut crate::sshbuf::sshbuf,
) {
    let mut fd: libc::c_int = -(1 as libc::c_int);
    let mut success: libc::c_int = 0 as libc::c_int;
    if options.expose_userauth_info == 0 || info.is_null() {
        return;
    }
    temporarily_use_uid(pw);
    auth_info_file = crate::xmalloc::xstrdup(
        b"/tmp/sshauth.XXXXXXXXXXXXXXX\0" as *const u8 as *const libc::c_char,
    );
    fd = _ssh_mkstemp(auth_info_file);
    if fd == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"prepare_auth_info_file\0",
            ))
            .as_ptr(),
            270 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"mkstemp: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    } else if atomicio(
        ::core::mem::transmute::<
            Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
            Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
        >(Some(
            write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
        )),
        fd,
        crate::sshbuf::sshbuf_mutable_ptr(info) as *mut libc::c_void,
        crate::sshbuf::sshbuf_len(info),
    ) != crate::sshbuf::sshbuf_len(info)
    {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"prepare_auth_info_file\0",
            ))
            .as_ptr(),
            275 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"write: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    } else if close(fd) != 0 as libc::c_int {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"prepare_auth_info_file\0",
            ))
            .as_ptr(),
            279 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"close: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    } else {
        success = 1 as libc::c_int;
    }
    if success == 0 {
        if fd != -(1 as libc::c_int) {
            close(fd);
        }
        libc::free(auth_info_file as *mut libc::c_void);
        auth_info_file = 0 as *mut libc::c_char;
    }
    restore_uid();
}
unsafe extern "C" fn set_fwdpermit_from_authopts(mut ssh: *mut ssh, mut _opts: *const sshauthopt) {
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut port: libc::c_int = 0;
    let mut i: size_t = 0;
    if options.allow_tcp_forwarding & (1 as libc::c_int) << 1 as libc::c_int != 0 as libc::c_int {
        channel_clear_permission(
            ssh,
            0x101 as libc::c_int,
            (1 as libc::c_int) << 1 as libc::c_int,
        );
        i = 0 as libc::c_int as size_t;
        while i < (*auth_opts).npermitopen {
            cp = crate::xmalloc::xstrdup(*((*auth_opts).permitopen).offset(i as isize));
            tmp = cp;
            host = hpdelim2(&mut cp, 0 as *mut libc::c_char);
            if host.is_null() {
                sshfatal(
                    b"session.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                        b"set_fwdpermit_from_authopts\0",
                    ))
                    .as_ptr(),
                    306 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"internal error: hpdelim\0" as *const u8 as *const libc::c_char,
                );
            }
            host = cleanhostname(host);
            if cp.is_null() || {
                port = permitopen_port(cp);
                port < 0 as libc::c_int
            } {
                sshfatal(
                    b"session.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                        b"set_fwdpermit_from_authopts\0",
                    ))
                    .as_ptr(),
                    309 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"internal error: permitopen port\0" as *const u8 as *const libc::c_char,
                );
            }
            channel_add_permission(
                ssh,
                0x101 as libc::c_int,
                (1 as libc::c_int) << 1 as libc::c_int,
                host,
                port,
            );
            libc::free(tmp as *mut libc::c_void);
            i = i.wrapping_add(1);
            i;
        }
    }
    if options.allow_tcp_forwarding & 1 as libc::c_int != 0 as libc::c_int {
        channel_clear_permission(ssh, 0x101 as libc::c_int, 1 as libc::c_int);
        i = 0 as libc::c_int as size_t;
        while i < (*auth_opts).npermitlisten {
            cp = crate::xmalloc::xstrdup(*((*auth_opts).permitlisten).offset(i as isize));
            tmp = cp;
            host = hpdelim(&mut cp);
            if host.is_null() {
                sshfatal(
                    b"session.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                        b"set_fwdpermit_from_authopts\0",
                    ))
                    .as_ptr(),
                    321 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"internal error: hpdelim\0" as *const u8 as *const libc::c_char,
                );
            }
            host = cleanhostname(host);
            if cp.is_null() || {
                port = permitopen_port(cp);
                port < 0 as libc::c_int
            } {
                sshfatal(
                    b"session.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                        b"set_fwdpermit_from_authopts\0",
                    ))
                    .as_ptr(),
                    324 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"internal error: permitlisten port\0" as *const u8 as *const libc::c_char,
                );
            }
            channel_add_permission(ssh, 0x101 as libc::c_int, 1 as libc::c_int, host, port);
            libc::free(tmp as *mut libc::c_void);
            i = i.wrapping_add(1);
            i;
        }
    }
}
pub unsafe extern "C" fn do_authenticated(mut ssh: *mut ssh, mut authctxt: *mut Authctxt) {
    setproctitle(
        b"%s\0" as *const u8 as *const libc::c_char,
        (*(*authctxt).pw).pw_name,
    );
    auth_log_authopts(
        b"active\0" as *const u8 as *const libc::c_char,
        auth_opts,
        0 as libc::c_int,
    );
    set_fwdpermit_from_authopts(ssh, auth_opts);
    if (*auth_opts).permit_port_forwarding_flag == 0 || options.disable_forwarding != 0 {
        channel_disable_admin(ssh, (1 as libc::c_int) << 1 as libc::c_int);
        channel_disable_admin(ssh, 1 as libc::c_int);
    } else {
        if options.allow_tcp_forwarding & (1 as libc::c_int) << 1 as libc::c_int == 0 as libc::c_int
        {
            channel_disable_admin(ssh, (1 as libc::c_int) << 1 as libc::c_int);
        } else {
            channel_permit_all(ssh, (1 as libc::c_int) << 1 as libc::c_int);
        }
        if options.allow_tcp_forwarding & 1 as libc::c_int == 0 as libc::c_int {
            channel_disable_admin(ssh, 1 as libc::c_int);
        } else {
            channel_permit_all(ssh, 1 as libc::c_int);
        }
    }
    auth_debug_send(ssh);
    prepare_auth_info_file((*authctxt).pw, (*authctxt).session_info);
    do_authenticated2(ssh, authctxt);
    do_cleanup(ssh, authctxt);
}
unsafe extern "C" fn xauth_valid_string(mut s: *const libc::c_char) -> libc::c_int {
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while *s.offset(i as isize) as libc::c_int != '\0' as i32 {
        if *(*__ctype_b_loc()).offset(*s.offset(i as isize) as u_char as libc::c_int as isize)
            as libc::c_int
            & _ISalnum as libc::c_int as libc::c_ushort as libc::c_int
            == 0
            && *s.offset(i as isize) as libc::c_int != '.' as i32
            && *s.offset(i as isize) as libc::c_int != ':' as i32
            && *s.offset(i as isize) as libc::c_int != '/' as i32
            && *s.offset(i as isize) as libc::c_int != '-' as i32
            && *s.offset(i as isize) as libc::c_int != '_' as i32
        {
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn do_exec_no_pty(
    mut ssh: *mut ssh,
    mut s: *mut Session,
    mut command: *const libc::c_char,
) -> libc::c_int {
    let mut pid: pid_t = 0;
    let mut pin: [libc::c_int; 2] = [0; 2];
    let mut pout: [libc::c_int; 2] = [0; 2];
    let mut perr: [libc::c_int; 2] = [0; 2];
    if s.is_null() {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_exec_no_pty\0"))
                .as_ptr(),
            395 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"do_exec_no_pty: no session\0" as *const u8 as *const libc::c_char,
        );
    }
    if pipe(pin.as_mut_ptr()) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_exec_no_pty\0"))
                .as_ptr(),
            399 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"pipe in: %.100s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    if pipe(pout.as_mut_ptr()) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_exec_no_pty\0"))
                .as_ptr(),
            403 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"pipe out: %.100s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        close(pin[0 as libc::c_int as usize]);
        close(pin[1 as libc::c_int as usize]);
        return -(1 as libc::c_int);
    }
    if pipe(perr.as_mut_ptr()) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_exec_no_pty\0"))
                .as_ptr(),
            409 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"pipe err: %.100s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        close(pin[0 as libc::c_int as usize]);
        close(pin[1 as libc::c_int as usize]);
        close(pout[0 as libc::c_int as usize]);
        close(pout[1 as libc::c_int as usize]);
        return -(1 as libc::c_int);
    }
    session_proctitle(s);
    pid = libc::fork();
    match pid {
        -1 => {
            crate::log::sshlog(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"do_exec_no_pty\0"))
                    .as_ptr(),
                440 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"libc::fork: %.100s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
            close(pin[0 as libc::c_int as usize]);
            close(pin[1 as libc::c_int as usize]);
            close(pout[0 as libc::c_int as usize]);
            close(pout[1 as libc::c_int as usize]);
            close(perr[0 as libc::c_int as usize]);
            close(perr[1 as libc::c_int as usize]);
            return -(1 as libc::c_int);
        }
        0 => {
            is_child = 1 as libc::c_int;
            if setsid() == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"session.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"do_exec_no_pty\0",
                    ))
                    .as_ptr(),
                    463 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"setsid failed: %.100s\0" as *const u8 as *const libc::c_char,
                    libc::strerror(*libc::__errno_location()),
                );
            }
            close(pin[1 as libc::c_int as usize]);
            if libc::dup2(pin[0 as libc::c_int as usize], 0 as libc::c_int) == -(1 as libc::c_int) {
                libc::perror(b"libc::dup2 stdin\0" as *const u8 as *const libc::c_char);
            }
            close(pin[0 as libc::c_int as usize]);
            close(pout[0 as libc::c_int as usize]);
            if libc::dup2(pout[1 as libc::c_int as usize], 1 as libc::c_int) == -(1 as libc::c_int)
            {
                libc::perror(b"libc::dup2 stdout\0" as *const u8 as *const libc::c_char);
            }
            close(pout[1 as libc::c_int as usize]);
            close(perr[0 as libc::c_int as usize]);
            if libc::dup2(perr[1 as libc::c_int as usize], 2 as libc::c_int) == -(1 as libc::c_int)
            {
                libc::perror(b"libc::dup2 stderr\0" as *const u8 as *const libc::c_char);
            }
            close(perr[1 as libc::c_int as usize]);
            do_child(ssh, s, command);
        }
        _ => {}
    }
    (*s).pid = pid;
    ssh_packet_set_interactive(
        ssh,
        ((*s).display != 0 as *mut libc::c_void as *mut libc::c_char) as libc::c_int,
        options.ip_qos_interactive,
        options.ip_qos_bulk,
    );
    crate::sshbuf::sshbuf_reset(loginmsg);
    close(pin[0 as libc::c_int as usize]);
    close(pout[1 as libc::c_int as usize]);
    close(perr[1 as libc::c_int as usize]);
    session_set_fds(
        ssh,
        s,
        pin[1 as libc::c_int as usize],
        pout[0 as libc::c_int as usize],
        perr[0 as libc::c_int as usize],
        (*s).is_subsystem,
        0 as libc::c_int,
    );
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn do_exec_pty(
    mut ssh: *mut ssh,
    mut s: *mut Session,
    mut command: *const libc::c_char,
) -> libc::c_int {
    let mut fdout: libc::c_int = 0;
    let mut ptyfd: libc::c_int = 0;
    let mut ttyfd: libc::c_int = 0;
    let mut ptymaster: libc::c_int = 0;
    let mut pid: pid_t = 0;
    if s.is_null() {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_exec_pty\0")).as_ptr(),
            563 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"do_exec_pty: no session\0" as *const u8 as *const libc::c_char,
        );
    }
    ptyfd = (*s).ptyfd;
    ttyfd = (*s).ttyfd;
    fdout = dup(ptyfd);
    if fdout == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_exec_pty\0")).as_ptr(),
            575 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"dup #1: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        close(ttyfd);
        close(ptyfd);
        return -(1 as libc::c_int);
    }
    ptymaster = dup(ptyfd);
    if ptymaster == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_exec_pty\0")).as_ptr(),
            582 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"dup #2: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        close(ttyfd);
        close(ptyfd);
        close(fdout);
        return -(1 as libc::c_int);
    }
    pid = libc::fork();
    match pid {
        -1 => {
            crate::log::sshlog(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_exec_pty\0"))
                    .as_ptr(),
                592 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"libc::fork: %.100s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
            close(fdout);
            close(ptymaster);
            close(ttyfd);
            close(ptyfd);
            return -(1 as libc::c_int);
        }
        0 => {
            is_child = 1 as libc::c_int;
            close(fdout);
            close(ptymaster);
            close(ptyfd);
            pty_make_controlling_tty(&mut ttyfd, ((*s).tty).as_mut_ptr());
            if libc::dup2(ttyfd, 0 as libc::c_int) == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"session.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_exec_pty\0"))
                        .as_ptr(),
                    612 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"libc::dup2 stdin: %s\0" as *const u8 as *const libc::c_char,
                    libc::strerror(*libc::__errno_location()),
                );
            }
            if libc::dup2(ttyfd, 1 as libc::c_int) == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"session.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_exec_pty\0"))
                        .as_ptr(),
                    614 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"libc::dup2 stdout: %s\0" as *const u8 as *const libc::c_char,
                    libc::strerror(*libc::__errno_location()),
                );
            }
            if libc::dup2(ttyfd, 2 as libc::c_int) == -(1 as libc::c_int) {
                crate::log::sshlog(
                    b"session.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_exec_pty\0"))
                        .as_ptr(),
                    616 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"libc::dup2 stderr: %s\0" as *const u8 as *const libc::c_char,
                    libc::strerror(*libc::__errno_location()),
                );
            }
            close(ttyfd);
            do_login(ssh, s, command);
            do_child(ssh, s, command);
        }
        _ => {}
    }
    (*s).pid = pid;
    close(ttyfd);
    (*s).ptymaster = ptymaster;
    ssh_packet_set_interactive(
        ssh,
        1 as libc::c_int,
        options.ip_qos_interactive,
        options.ip_qos_bulk,
    );
    session_set_fds(
        ssh,
        s,
        ptyfd,
        fdout,
        -(1 as libc::c_int),
        1 as libc::c_int,
        1 as libc::c_int,
    );
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn do_exec(
    mut ssh: *mut ssh,
    mut s: *mut Session,
    mut command: *const libc::c_char,
) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    let mut forced: *const libc::c_char = 0 as *const libc::c_char;
    let mut tty: *const libc::c_char = 0 as *const libc::c_char;
    let mut session_type: [libc::c_char; 1024] = [0; 1024];
    if !(options.adm_forced_command).is_null() {
        original_command = command;
        command = options.adm_forced_command;
        forced = b"(config)\0" as *const u8 as *const libc::c_char;
    } else if !((*auth_opts).force_command).is_null() {
        original_command = command;
        command = (*auth_opts).force_command;
        forced = b"(key-option)\0" as *const u8 as *const libc::c_char;
    }
    (*s).forced = 0 as libc::c_int;
    if !forced.is_null() {
        (*s).forced = 1 as libc::c_int;
        if strncmp(
            command,
            b"internal-sftp\0" as *const u8 as *const libc::c_char,
            (::core::mem::size_of::<[libc::c_char; 14]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        ) == 0
            && (*command.offset(
                (::core::mem::size_of::<[libc::c_char; 14]>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize,
            ) as libc::c_int
                == '\0' as i32
                || *command.offset(
                    (::core::mem::size_of::<[libc::c_char; 14]>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                        as isize,
                ) as libc::c_int
                    == ' ' as i32
                || *command.offset(
                    (::core::mem::size_of::<[libc::c_char; 14]>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                        as isize,
                ) as libc::c_int
                    == '\t' as i32)
        {
            (*s).is_subsystem = if (*s).is_subsystem != 0 {
                2 as libc::c_int
            } else {
                3 as libc::c_int
            };
        } else if (*s).is_subsystem != 0 {
            (*s).is_subsystem = 1 as libc::c_int;
        }
        libc::snprintf(
            session_type.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
            b"forced-command %s '%.900s'\0" as *const u8 as *const libc::c_char,
            forced,
            command,
        );
    } else if (*s).is_subsystem != 0 {
        libc::snprintf(
            session_type.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
            b"subsystem '%.900s'\0" as *const u8 as *const libc::c_char,
            (*s).subsys,
        );
    } else if command.is_null() {
        libc::snprintf(
            session_type.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
            b"shell\0" as *const u8 as *const libc::c_char,
        );
    } else {
        libc::snprintf(
            session_type.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
            b"command\0" as *const u8 as *const libc::c_char,
        );
    }
    if (*s).ttyfd != -(1 as libc::c_int) {
        tty = ((*s).tty).as_mut_ptr();
        if strncmp(
            tty,
            b"/dev/\0" as *const u8 as *const libc::c_char,
            5 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            tty = tty.offset(5 as libc::c_int as isize);
        }
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 8], &[libc::c_char; 8]>(b"do_exec\0")).as_ptr(),
        705 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_VERBOSE,
        0 as *const libc::c_char,
        b"Starting session: %s%s%s for %s from %.200s port %d id %d\0" as *const u8
            as *const libc::c_char,
        session_type.as_mut_ptr(),
        if tty.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b" on \0" as *const u8 as *const libc::c_char
        },
        if tty.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            tty
        },
        (*(*s).pw).pw_name,
        ssh_remote_ipaddr(ssh),
        ssh_remote_port(ssh),
        (*s).self_0,
    );
    if (*s).ttyfd != -(1 as libc::c_int) {
        ret = do_exec_pty(ssh, s, command);
    } else {
        ret = do_exec_no_pty(ssh, s, command);
    }
    original_command = 0 as *const libc::c_char;
    crate::sshbuf::sshbuf_reset(loginmsg);
    return ret;
}
pub unsafe extern "C" fn do_login(
    mut ssh: *mut ssh,
    mut s: *mut Session,
    mut command: *const libc::c_char,
) {
    let mut fromlen: socklen_t = 0;
    let mut from: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut pw: *mut libc::passwd = (*s).pw;
    let mut pid: pid_t = libc::getpid();
    memset(
        &mut from as *mut sockaddr_storage as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong,
    );
    fromlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    if ssh_packet_connection_is_on_socket(ssh) != 0 {
        if getpeername(
            ssh_packet_get_connection_in(ssh),
            __SOCKADDR_ARG {
                __sockaddr__: &mut from as *mut sockaddr_storage as *mut sockaddr,
            },
            &mut fromlen,
        ) == -(1 as libc::c_int)
        {
            crate::log::sshlog(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_login\0")).as_ptr(),
                753 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"getpeername: %.100s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
            cleanup_exit(255 as libc::c_int);
        }
    }
    if use_privsep == 0 {
        record_login(
            pid,
            ((*s).tty).as_mut_ptr(),
            (*pw).pw_name,
            (*pw).pw_uid,
            session_get_remote_name_or_ip(ssh, utmp_len, options.use_dns),
            &mut from as *mut sockaddr_storage as *mut sockaddr,
            fromlen,
        );
    }
    if check_quietlogin(s, command) != 0 {
        return;
    }
    display_loginmsg();
    do_motd();
}
pub unsafe extern "C" fn do_motd() {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut buf: [libc::c_char; 256] = [0; 256];
    if options.print_motd != 0 {
        f = fopen(
            b"/etc/motd\0" as *const u8 as *const libc::c_char,
            b"r\0" as *const u8 as *const libc::c_char,
        );
        if !f.is_null() {
            while !(fgets(
                buf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong as libc::c_int,
                f,
            ))
            .is_null()
            {
                fputs(buf.as_mut_ptr(), stdout);
            }
            fclose(f);
        }
    }
}
pub unsafe extern "C" fn check_quietlogin(
    mut s: *mut Session,
    mut command: *const libc::c_char,
) -> libc::c_int {
    let mut buf: [libc::c_char; 256] = [0; 256];
    let mut pw: *mut libc::passwd = (*s).pw;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if !command.is_null() {
        return 1 as libc::c_int;
    }
    libc::snprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
        b"%.200s/.hushlogin\0" as *const u8 as *const libc::c_char,
        (*pw).pw_dir,
    );
    if libc::stat(buf.as_mut_ptr(), &mut st) >= 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn read_environment_file(
    mut env: *mut *mut *mut libc::c_char,
    mut envsize: *mut u_int,
    mut filename: *const libc::c_char,
    mut allowlist: *const libc::c_char,
) {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut value: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut lineno: u_int = 0 as libc::c_int as u_int;
    f = fopen(filename, b"r\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        return;
    }
    while getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long {
        lineno = lineno.wrapping_add(1);
        if lineno > 1000 as libc::c_int as libc::c_uint {
            sshfatal(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"read_environment_file\0",
                ))
                .as_ptr(),
                858 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Too many lines in environment file %s\0" as *const u8 as *const libc::c_char,
                filename,
            );
        }
        cp = line;
        while *cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32 {
            cp = cp.offset(1);
            cp;
        }
        if *cp == 0 || *cp as libc::c_int == '#' as i32 || *cp as libc::c_int == '\n' as i32 {
            continue;
        }
        *cp.offset(strcspn(cp, b"\n\0" as *const u8 as *const libc::c_char) as isize) =
            '\0' as i32 as libc::c_char;
        value = libc::strchr(cp, '=' as i32);
        if value.is_null() {
            libc::fprintf(
                stderr,
                b"Bad line %u in %.100s\n\0" as *const u8 as *const libc::c_char,
                lineno,
                filename,
            );
        } else {
            *value = '\0' as i32 as libc::c_char;
            value = value.offset(1);
            value;
            if !allowlist.is_null()
                && match_pattern_list(cp, allowlist, 0 as libc::c_int) != 1 as libc::c_int
            {
                continue;
            }
            child_set_env(env, envsize, cp, value);
        }
    }
    libc::free(line as *mut libc::c_void);
    fclose(f);
}
unsafe extern "C" fn do_setup_env(
    mut ssh: *mut ssh,
    mut s: *mut Session,
    mut shell: *const libc::c_char,
) -> *mut *mut libc::c_char {
    let mut buf: [libc::c_char; 256] = [0; 256];
    let mut n: size_t = 0;
    let mut i: u_int = 0;
    let mut envsize: u_int = 0;
    let mut ocp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut value: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut env: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut laddr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pw: *mut libc::passwd = (*s).pw;
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    envsize = 100 as libc::c_int as u_int;
    env = crate::xmalloc::xcalloc(
        envsize as size_t,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    let ref mut fresh0 = *env.offset(0 as libc::c_int as isize);
    *fresh0 = 0 as *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while i < (*s).num_env {
        child_set_env(
            &mut env,
            &mut envsize,
            (*((*s).env).offset(i as isize)).name,
            (*((*s).env).offset(i as isize)).val,
        );
        i = i.wrapping_add(1);
        i;
    }
    child_set_env(
        &mut env,
        &mut envsize,
        b"USER\0" as *const u8 as *const libc::c_char,
        (*pw).pw_name,
    );
    child_set_env(
        &mut env,
        &mut envsize,
        b"LOGNAME\0" as *const u8 as *const libc::c_char,
        (*pw).pw_name,
    );
    child_set_env(
        &mut env,
        &mut envsize,
        b"HOME\0" as *const u8 as *const libc::c_char,
        (*pw).pw_dir,
    );
    if path.is_null() || *path as libc::c_int == '\0' as i32 {
        child_set_env(
            &mut env,
            &mut envsize,
            b"PATH\0" as *const u8 as *const libc::c_char,
            if (*(*s).pw).pw_uid == 0 as libc::c_int as libc::c_uint {
                b"/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin\0" as *const u8
                    as *const libc::c_char
            } else {
                b"/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin\0" as *const u8
                    as *const libc::c_char
            },
        );
    }
    if options.use_pam == 0 {
        libc::snprintf(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
            b"%.200s/%.50s\0" as *const u8 as *const libc::c_char,
            b"/var/mail\0" as *const u8 as *const libc::c_char,
            (*pw).pw_name,
        );
        child_set_env(
            &mut env,
            &mut envsize,
            b"MAIL\0" as *const u8 as *const libc::c_char,
            buf.as_mut_ptr(),
        );
    }
    child_set_env(
        &mut env,
        &mut envsize,
        b"SHELL\0" as *const u8 as *const libc::c_char,
        shell,
    );
    if !(getenv(b"TZ\0" as *const u8 as *const libc::c_char)).is_null() {
        child_set_env(
            &mut env,
            &mut envsize,
            b"TZ\0" as *const u8 as *const libc::c_char,
            getenv(b"TZ\0" as *const u8 as *const libc::c_char),
        );
    }
    if !((*s).term).is_null() {
        child_set_env(
            &mut env,
            &mut envsize,
            b"TERM\0" as *const u8 as *const libc::c_char,
            (*s).term,
        );
    }
    if !((*s).display).is_null() {
        child_set_env(
            &mut env,
            &mut envsize,
            b"DISPLAY\0" as *const u8 as *const libc::c_char,
            (*s).display,
        );
    }
    let mut cp_0: *mut libc::c_char = 0 as *mut libc::c_char;
    cp_0 = getenv(b"KRB5CCNAME\0" as *const u8 as *const libc::c_char);
    if !cp_0.is_null() {
        child_set_env(
            &mut env,
            &mut envsize,
            b"KRB5CCNAME\0" as *const u8 as *const libc::c_char,
            cp_0,
        );
    }
    if !auth_sock_name.is_null() {
        child_set_env(
            &mut env,
            &mut envsize,
            b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char,
            auth_sock_name,
        );
    }
    if options.permit_user_env != 0 {
        n = 0 as libc::c_int as size_t;
        while n < (*auth_opts).nenv {
            ocp = crate::xmalloc::xstrdup(*((*auth_opts).env).offset(n as isize));
            cp = libc::strchr(ocp, '=' as i32);
            if !cp.is_null() {
                *cp = '\0' as i32 as libc::c_char;
                if (options.permit_user_env_allowlist).is_null()
                    || match_pattern_list(ocp, options.permit_user_env_allowlist, 0 as libc::c_int)
                        == 1 as libc::c_int
                {
                    child_set_env(
                        &mut env,
                        &mut envsize,
                        ocp,
                        cp.offset(1 as libc::c_int as isize),
                    );
                }
            }
            libc::free(ocp as *mut libc::c_void);
            n = n.wrapping_add(1);
            n;
        }
    }
    if options.permit_user_env != 0 {
        libc::snprintf(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
            b"%.200s/%s/environment\0" as *const u8 as *const libc::c_char,
            (*pw).pw_dir,
            b".ssh\0" as *const u8 as *const libc::c_char,
        );
        read_environment_file(
            &mut env,
            &mut envsize,
            buf.as_mut_ptr(),
            options.permit_user_env_allowlist,
        );
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_setenv {
        cp = crate::xmalloc::xstrdup(*(options.setenv).offset(i as isize));
        value = libc::strchr(cp, '=' as i32);
        if value.is_null() {
            sshfatal(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"do_setup_env\0"))
                    .as_ptr(),
                1157 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Invalid config SetEnv: %s\0" as *const u8 as *const libc::c_char,
                *(options.setenv).offset(i as isize),
            );
        }
        let fresh1 = value;
        value = value.offset(1);
        *fresh1 = '\0' as i32 as libc::c_char;
        child_set_env(&mut env, &mut envsize, cp, value);
        libc::free(cp as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::snprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
        b"%.50s %d %d\0" as *const u8 as *const libc::c_char,
        ssh_remote_ipaddr(ssh),
        ssh_remote_port(ssh),
        ssh_local_port(ssh),
    );
    child_set_env(
        &mut env,
        &mut envsize,
        b"SSH_CLIENT\0" as *const u8 as *const libc::c_char,
        buf.as_mut_ptr(),
    );
    laddr = get_local_ipaddr(ssh_packet_get_connection_in(ssh));
    libc::snprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
        b"%.50s %d %.50s %d\0" as *const u8 as *const libc::c_char,
        ssh_remote_ipaddr(ssh),
        ssh_remote_port(ssh),
        laddr,
        ssh_local_port(ssh),
    );
    libc::free(laddr as *mut libc::c_void);
    child_set_env(
        &mut env,
        &mut envsize,
        b"SSH_CONNECTION\0" as *const u8 as *const libc::c_char,
        buf.as_mut_ptr(),
    );
    if !tun_fwd_ifnames.is_null() {
        child_set_env(
            &mut env,
            &mut envsize,
            b"SSH_TUNNEL\0" as *const u8 as *const libc::c_char,
            tun_fwd_ifnames,
        );
    }
    if !auth_info_file.is_null() {
        child_set_env(
            &mut env,
            &mut envsize,
            b"SSH_USER_AUTH\0" as *const u8 as *const libc::c_char,
            auth_info_file,
        );
    }
    if (*s).ttyfd != -(1 as libc::c_int) {
        child_set_env(
            &mut env,
            &mut envsize,
            b"SSH_TTY\0" as *const u8 as *const libc::c_char,
            ((*s).tty).as_mut_ptr(),
        );
    }
    if !original_command.is_null() {
        child_set_env(
            &mut env,
            &mut envsize,
            b"SSH_ORIGINAL_COMMAND\0" as *const u8 as *const libc::c_char,
            original_command,
        );
    }
    if debug_flag != 0 {
        libc::fprintf(
            stderr,
            b"Environment:\n\0" as *const u8 as *const libc::c_char,
        );
        i = 0 as libc::c_int as u_int;
        while !(*env.offset(i as isize)).is_null() {
            libc::fprintf(
                stderr,
                b"  %.200s\n\0" as *const u8 as *const libc::c_char,
                *env.offset(i as isize),
            );
            i = i.wrapping_add(1);
            i;
        }
    }
    return env;
}
unsafe extern "C" fn do_rc_files(
    mut _ssh: *mut ssh,
    mut s: *mut Session,
    mut shell: *const libc::c_char,
) {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut cmd: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut user_rc: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut do_xauth: libc::c_int = 0;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    do_xauth = (!((*s).display).is_null()
        && !((*s).auth_proto).is_null()
        && !((*s).auth_data).is_null()) as libc::c_int;
    crate::xmalloc::xasprintf(
        &mut user_rc as *mut *mut libc::c_char,
        b"%s/%s\0" as *const u8 as *const libc::c_char,
        (*(*s).pw).pw_dir,
        b".ssh/rc\0" as *const u8 as *const libc::c_char,
    );
    if (*s).is_subsystem == 0
        && (options.adm_forced_command).is_null()
        && (*auth_opts).permit_user_rc != 0
        && options.permit_user_rc != 0
        && libc::stat(user_rc, &mut st) >= 0 as libc::c_int
    {
        if crate::xmalloc::xasprintf(
            &mut cmd as *mut *mut libc::c_char,
            b"%s -c '%s %s'\0" as *const u8 as *const libc::c_char,
            shell,
            b"/bin/sh\0" as *const u8 as *const libc::c_char,
            user_rc,
        ) == -(1 as libc::c_int)
        {
            sshfatal(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_rc_files\0"))
                    .as_ptr(),
                1218 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::xmalloc::xasprintf: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        if debug_flag != 0 {
            libc::fprintf(
                stderr,
                b"Running %s\n\0" as *const u8 as *const libc::c_char,
                cmd,
            );
        }
        f = popen(cmd, b"w\0" as *const u8 as *const libc::c_char);
        if !f.is_null() {
            if do_xauth != 0 {
                libc::fprintf(
                    f,
                    b"%s %s\n\0" as *const u8 as *const libc::c_char,
                    (*s).auth_proto,
                    (*s).auth_data,
                );
            }
            pclose(f);
        } else {
            libc::fprintf(
                stderr,
                b"Could not run %s\n\0" as *const u8 as *const libc::c_char,
                user_rc,
            );
        }
    } else if libc::stat(
        b"/usr/local/etc/sshrc\0" as *const u8 as *const libc::c_char,
        &mut st,
    ) >= 0 as libc::c_int
    {
        if debug_flag != 0 {
            libc::fprintf(
                stderr,
                b"Running %s %s\n\0" as *const u8 as *const libc::c_char,
                b"/bin/sh\0" as *const u8 as *const libc::c_char,
                b"/usr/local/etc/sshrc\0" as *const u8 as *const libc::c_char,
            );
        }
        f = popen(
            b"/bin/sh /usr/local/etc/sshrc\0" as *const u8 as *const libc::c_char,
            b"w\0" as *const u8 as *const libc::c_char,
        );
        if !f.is_null() {
            if do_xauth != 0 {
                libc::fprintf(
                    f,
                    b"%s %s\n\0" as *const u8 as *const libc::c_char,
                    (*s).auth_proto,
                    (*s).auth_data,
                );
            }
            pclose(f);
        } else {
            libc::fprintf(
                stderr,
                b"Could not run %s\n\0" as *const u8 as *const libc::c_char,
                b"/usr/local/etc/sshrc\0" as *const u8 as *const libc::c_char,
            );
        }
    } else if do_xauth != 0 && !(options.xauth_location).is_null() {
        if debug_flag != 0 {
            libc::fprintf(
                stderr,
                b"Running %.500s remove %.100s\n\0" as *const u8 as *const libc::c_char,
                options.xauth_location,
                (*s).auth_display,
            );
            libc::fprintf(
                stderr,
                b"%.500s add %.100s %.100s %.100s\n\0" as *const u8 as *const libc::c_char,
                options.xauth_location,
                (*s).auth_display,
                (*s).auth_proto,
                (*s).auth_data,
            );
        }
        if crate::xmalloc::xasprintf(
            &mut cmd as *mut *mut libc::c_char,
            b"%s -q -\0" as *const u8 as *const libc::c_char,
            options.xauth_location,
        ) == -(1 as libc::c_int)
        {
            sshfatal(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_rc_files\0"))
                    .as_ptr(),
                1255 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::xmalloc::xasprintf: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        f = popen(cmd, b"w\0" as *const u8 as *const libc::c_char);
        if !f.is_null() {
            libc::fprintf(
                f,
                b"remove %s\n\0" as *const u8 as *const libc::c_char,
                (*s).auth_display,
            );
            libc::fprintf(
                f,
                b"add %s %s %s\n\0" as *const u8 as *const libc::c_char,
                (*s).auth_display,
                (*s).auth_proto,
                (*s).auth_data,
            );
            pclose(f);
        } else {
            libc::fprintf(
                stderr,
                b"Could not run %s\n\0" as *const u8 as *const libc::c_char,
                cmd,
            );
        }
    }
    libc::free(cmd as *mut libc::c_void);
    libc::free(user_rc as *mut libc::c_void);
}
unsafe extern "C" fn do_nologin(mut pw: *mut libc::passwd) {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut nl: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut def_nl: *mut libc::c_char =
        b"/etc/nologin\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    if (*pw).pw_uid == 0 as libc::c_int as libc::c_uint {
        return;
    }
    nl = def_nl;
    if libc::stat(nl, &mut sb) == -(1 as libc::c_int) {
        return;
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_nologin\0")).as_ptr(),
        1293 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"User %.100s not allowed because %s exists\0" as *const u8 as *const libc::c_char,
        (*pw).pw_name,
        nl,
    );
    f = fopen(nl, b"r\0" as *const u8 as *const libc::c_char);
    if !f.is_null() {
        while !(fgets(
            buf.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong as libc::c_int,
            f,
        ))
        .is_null()
        {
            fputs(buf.as_mut_ptr(), stderr);
        }
        fclose(f);
    }
    libc::exit(254 as libc::c_int);
}
unsafe extern "C" fn safely_chroot(mut path: *const libc::c_char, mut _uid: uid_t) {
    let mut cp: *const libc::c_char = 0 as *const libc::c_char;
    let mut component: [libc::c_char; 4096] = [0; 4096];
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if path_absolute(path) == 0 {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"safely_chroot\0"))
                .as_ptr(),
            1314 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"chroot path does not begin at root\0" as *const u8 as *const libc::c_char,
        );
    }
    if strlen(path) >= ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"safely_chroot\0"))
                .as_ptr(),
            1316 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"chroot path too long\0" as *const u8 as *const libc::c_char,
        );
    }
    cp = path;
    while !cp.is_null() {
        cp = libc::strchr(cp, '/' as i32);
        if cp.is_null() {
            strlcpy(
                component.as_mut_ptr(),
                path,
                ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
            );
        } else {
            cp = cp.offset(1);
            cp;
            memcpy(
                component.as_mut_ptr() as *mut libc::c_void,
                path as *const libc::c_void,
                cp.offset_from(path) as libc::c_long as libc::c_ulong,
            );
            component[cp.offset_from(path) as libc::c_long as usize] = '\0' as i32 as libc::c_char;
        }
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"safely_chroot\0"))
                .as_ptr(),
            1331 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"checking '%s'\0" as *const u8 as *const libc::c_char,
            component.as_mut_ptr(),
        );
        if libc::stat(component.as_mut_ptr(), &mut st) != 0 as libc::c_int {
            sshfatal(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"safely_chroot\0"))
                    .as_ptr(),
                1335 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"libc::stat(\"%s\"): %s\0" as *const u8 as *const libc::c_char,
                component.as_mut_ptr(),
                libc::strerror(*libc::__errno_location()),
            );
        }
        if st.st_uid != 0 as libc::c_int as libc::c_uint
            || st.st_mode & 0o22 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
        {
            sshfatal(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"safely_chroot\0"))
                    .as_ptr(),
                1339 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"bad ownership or modes for chroot directory %s\"%s\"\0" as *const u8
                    as *const libc::c_char,
                if cp.is_null() {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    b"component \0" as *const u8 as *const libc::c_char
                },
                component.as_mut_ptr(),
            );
        }
        if !(st.st_mode & 0o170000 as libc::c_int as libc::c_uint
            == 0o40000 as libc::c_int as libc::c_uint)
        {
            sshfatal(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"safely_chroot\0"))
                    .as_ptr(),
                1342 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"chroot path %s\"%s\" is not a directory\0" as *const u8 as *const libc::c_char,
                if cp.is_null() {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    b"component \0" as *const u8 as *const libc::c_char
                },
                component.as_mut_ptr(),
            );
        }
    }
    if chdir(path) == -(1 as libc::c_int) {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"safely_chroot\0"))
                .as_ptr(),
            1348 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Unable to chdir to chroot path \"%s\": %s\0" as *const u8 as *const libc::c_char,
            path,
            libc::strerror(*libc::__errno_location()),
        );
    }
    if chroot(path) == -(1 as libc::c_int) {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"safely_chroot\0"))
                .as_ptr(),
            1350 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"chroot(\"%s\"): %s\0" as *const u8 as *const libc::c_char,
            path,
            libc::strerror(*libc::__errno_location()),
        );
    }
    if chdir(b"/\0" as *const u8 as *const libc::c_char) == -(1 as libc::c_int) {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"safely_chroot\0"))
                .as_ptr(),
            1352 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"chdir(/) after chroot: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"safely_chroot\0")).as_ptr(),
        1353 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_VERBOSE,
        0 as *const libc::c_char,
        b"Changed root directory to \"%s\"\0" as *const u8 as *const libc::c_char,
        path,
    );
}
pub unsafe extern "C" fn do_setusercontext(mut pw: *mut libc::passwd) {
    let mut uidstr: [libc::c_char; 32] = [0; 32];
    let mut chroot_path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    platform_setusercontext(pw);
    if platform_privileged_uidswap() != 0 {
        if setlogin((*pw).pw_name) < 0 as libc::c_int {
            crate::log::sshlog(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"do_setusercontext\0"))
                    .as_ptr(),
                1373 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"setlogin failed: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
        if setgid((*pw).pw_gid) < 0 as libc::c_int {
            libc::perror(b"setgid\0" as *const u8 as *const libc::c_char);
            libc::exit(1 as libc::c_int);
        }
        if initgroups((*pw).pw_name, (*pw).pw_gid) < 0 as libc::c_int {
            libc::perror(b"initgroups\0" as *const u8 as *const libc::c_char);
            libc::exit(1 as libc::c_int);
        }
        endgrent();
        platform_setusercontext_post_groups(pw);
        if in_chroot == 0
            && !(options.chroot_directory).is_null()
            && strcasecmp(
                options.chroot_directory,
                b"none\0" as *const u8 as *const libc::c_char,
            ) != 0 as libc::c_int
        {
            tmp = tilde_expand_filename(options.chroot_directory, (*pw).pw_uid);
            libc::snprintf(
                uidstr.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
                b"%llu\0" as *const u8 as *const libc::c_char,
                (*pw).pw_uid as libc::c_ulonglong,
            );
            chroot_path = percent_expand(
                tmp,
                b"h\0" as *const u8 as *const libc::c_char,
                (*pw).pw_dir,
                b"u\0" as *const u8 as *const libc::c_char,
                (*pw).pw_name,
                b"U\0" as *const u8 as *const libc::c_char,
                uidstr.as_mut_ptr(),
                0 as *mut libc::c_void as *mut libc::c_char,
            );
            safely_chroot(chroot_path, (*pw).pw_uid);
            libc::free(tmp as *mut libc::c_void);
            libc::free(chroot_path as *mut libc::c_void);
            libc::free(options.chroot_directory as *mut libc::c_void);
            options.chroot_directory = 0 as *mut libc::c_char;
            in_chroot = 1 as libc::c_int;
        }
        permanently_set_uid(pw);
    } else if !(options.chroot_directory).is_null()
        && strcasecmp(
            options.chroot_directory,
            b"none\0" as *const u8 as *const libc::c_char,
        ) != 0 as libc::c_int
    {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"do_setusercontext\0"))
                .as_ptr(),
            1433 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"server lacks privileges to chroot to ChrootDirectory\0" as *const u8
                as *const libc::c_char,
        );
    }
    if libc::getuid() != (*pw).pw_uid || geteuid() != (*pw).pw_uid {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"do_setusercontext\0"))
                .as_ptr(),
            1437 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Failed to set uids to %u.\0" as *const u8 as *const libc::c_char,
            (*pw).pw_uid,
        );
    }
}
unsafe extern "C" fn do_pwchange(mut s: *mut Session) {
    libc::fflush(0 as *mut libc::FILE);
    libc::fprintf(
        stderr,
        b"WARNING: Your password has expired.\n\0" as *const u8 as *const libc::c_char,
    );
    if (*s).ttyfd != -(1 as libc::c_int) {
        libc::fprintf(
            stderr,
            b"You must change your password now and login again!\n\0" as *const u8
                as *const libc::c_char,
        );
        execl(
            b"/usr/bin/libc::passwd\0" as *const u8 as *const libc::c_char,
            b"libc::passwd\0" as *const u8 as *const libc::c_char,
            0 as *mut libc::c_void as *mut libc::c_char,
        );
        libc::perror(b"libc::passwd\0" as *const u8 as *const libc::c_char);
    } else {
        libc::fprintf(
            stderr,
            b"Password change required but no TTY available.\n\0" as *const u8
                as *const libc::c_char,
        );
    }
    libc::exit(1 as libc::c_int);
}
unsafe extern "C" fn child_close_fds(mut ssh: *mut ssh) {
    extern "C" {
        static mut auth_sock: libc::c_int;
    }
    if auth_sock != -(1 as libc::c_int) {
        close(auth_sock);
        auth_sock = -(1 as libc::c_int);
    }
    if ssh_packet_get_connection_in(ssh) == ssh_packet_get_connection_out(ssh) {
        close(ssh_packet_get_connection_in(ssh));
    } else {
        close(ssh_packet_get_connection_in(ssh));
        close(ssh_packet_get_connection_out(ssh));
    }
    channel_close_all(ssh);
    endpwent();
    log_redirect_stderr_to(0 as *const libc::c_char);
    closefrom(2 as libc::c_int + 1 as libc::c_int);
}
pub unsafe extern "C" fn do_child(
    mut ssh: *mut ssh,
    mut s: *mut Session,
    mut command: *const libc::c_char,
) {
    extern "C" {
        #[link_name = "environ"]
        static mut environ_0: *mut *mut libc::c_char;
    }
    let mut env: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut argv: [*mut libc::c_char; 10] = [0 as *mut libc::c_char; 10];
    let mut remote_id: [libc::c_char; 512] = [0; 512];
    let mut shell: *const libc::c_char = 0 as *const libc::c_char;
    let mut shell0: *const libc::c_char = 0 as *const libc::c_char;
    let mut pw: *mut libc::passwd = (*s).pw;
    let mut r: libc::c_int = 0 as libc::c_int;
    sshpkt_fmt_connection_id(
        ssh,
        remote_id.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
    );
    destroy_sensitive_data();
    ssh_packet_clear_keys(ssh);
    if (*(*s).authctxt).force_pwchange != 0 {
        do_setusercontext(pw);
        child_close_fds(ssh);
        do_pwchange(s);
        libc::exit(1 as libc::c_int);
    }
    if options.use_pam == 0 {
        do_nologin(pw);
    }
    do_setusercontext(pw);
    if check_quietlogin(s, command) == 0 {
        display_loginmsg();
    }
    shell = if *((*pw).pw_shell).offset(0 as libc::c_int as isize) as libc::c_int == '\0' as i32 {
        b"/bin/sh\0" as *const u8 as *const libc::c_char
    } else {
        (*pw).pw_shell as *const libc::c_char
    };
    env = do_setup_env(ssh, s, shell);
    child_close_fds(ssh);
    environ = env;
    if chdir((*pw).pw_dir) == -(1 as libc::c_int) {
        if r != 0 || in_chroot == 0 {
            libc::fprintf(
                stderr,
                b"Could not chdir to home directory %s: %s\n\0" as *const u8 as *const libc::c_char,
                (*pw).pw_dir,
                libc::strerror(*libc::__errno_location()),
            );
        }
        if r != 0 {
            libc::exit(1 as libc::c_int);
        }
    }
    closefrom(2 as libc::c_int + 1 as libc::c_int);
    do_rc_files(ssh, s, shell);
    crate::misc::ssh_signal(13 as libc::c_int, None);
    if (*s).is_subsystem == 3 as libc::c_int {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"do_child\0")).as_ptr(),
            1647 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Connection from %s: refusing non-sftp session\0" as *const u8 as *const libc::c_char,
            remote_id.as_mut_ptr(),
        );
        printf(
            b"This service allows sftp connections only.\n\0" as *const u8 as *const libc::c_char,
        );
        libc::fflush(0 as *mut libc::FILE);
        libc::exit(1 as libc::c_int);
    } else if (*s).is_subsystem == 2 as libc::c_int {
        extern "C" {
            #[link_name = "BSDoptind"]
            static mut BSDoptind_0: libc::c_int;
        }
        extern "C" {
            #[link_name = "BSDoptreset"]
            static mut BSDoptreset_0: libc::c_int;
        }
        let mut i: libc::c_int = 0;
        let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut args: *mut libc::c_char = 0 as *mut libc::c_char;
        setproctitle(
            b"%s@%s\0" as *const u8 as *const libc::c_char,
            (*(*s).pw).pw_name,
            b"internal-sftp\0" as *const u8 as *const libc::c_char,
        );
        args = crate::xmalloc::xstrdup(if !command.is_null() {
            command
        } else {
            b"sftp-server\0" as *const u8 as *const libc::c_char
        });
        i = 0 as libc::c_int;
        p = strtok(args, b" \0" as *const u8 as *const libc::c_char);
        while !p.is_null() {
            if i < 10 as libc::c_int - 1 as libc::c_int {
                let fresh2 = i;
                i = i + 1;
                argv[fresh2 as usize] = p;
            }
            p = strtok(
                0 as *mut libc::c_char,
                b" \0" as *const u8 as *const libc::c_char,
            );
        }
        argv[i as usize] = 0 as *mut libc::c_char;
        BSDoptreset = 1 as libc::c_int;
        BSDoptind = BSDoptreset;
        __progname = argv[0 as libc::c_int as usize];
        libc::exit(sftp_server_main(i, argv.as_mut_ptr(), (*s).pw));
    }
    libc::fflush(0 as *mut libc::FILE);
    shell0 = libc::strrchr(shell, '/' as i32);
    if !shell0.is_null() {
        shell0 = shell0.offset(1);
        shell0;
    } else {
        shell0 = shell;
    }
    if command.is_null() {
        let mut argv0: [libc::c_char; 256] = [0; 256];
        argv0[0 as libc::c_int as usize] = '-' as i32 as libc::c_char;
        if strlcpy(
            argv0.as_mut_ptr().offset(1 as libc::c_int as isize),
            shell0,
            (::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        ) >= (::core::mem::size_of::<[libc::c_char; 256]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        {
            *libc::__errno_location() = 22 as libc::c_int;
            libc::perror(shell);
            libc::exit(1 as libc::c_int);
        }
        argv[0 as libc::c_int as usize] = argv0.as_mut_ptr();
        argv[1 as libc::c_int as usize] = 0 as *mut libc::c_char;
        execve(
            shell,
            argv.as_mut_ptr() as *const *mut libc::c_char,
            env as *const *mut libc::c_char,
        );
        libc::perror(shell);
        libc::exit(1 as libc::c_int);
    }
    argv[0 as libc::c_int as usize] = shell0 as *mut libc::c_char;
    argv[1 as libc::c_int as usize] =
        b"-c\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    argv[2 as libc::c_int as usize] = command as *mut libc::c_char;
    argv[3 as libc::c_int as usize] = 0 as *mut libc::c_char;
    execve(
        shell,
        argv.as_mut_ptr() as *const *mut libc::c_char,
        env as *const *mut libc::c_char,
    );
    libc::perror(shell);
    libc::exit(1 as libc::c_int);
}
pub unsafe extern "C" fn session_unused(mut id: libc::c_int) {
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"session_unused\0")).as_ptr(),
        1721 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"session id %d unused\0" as *const u8 as *const libc::c_char,
        id,
    );
    if id >= options.max_sessions || id >= sessions_nalloc {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"session_unused\0"))
                .as_ptr(),
            1725 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"insane session id %d (max %d nalloc %d)\0" as *const u8 as *const libc::c_char,
            id,
            options.max_sessions,
            sessions_nalloc,
        );
    }
    memset(
        &mut *sessions.offset(id as isize) as *mut Session as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<Session>() as libc::c_ulong,
    );
    (*sessions.offset(id as isize)).self_0 = id;
    (*sessions.offset(id as isize)).used = 0 as libc::c_int;
    (*sessions.offset(id as isize)).chanid = -(1 as libc::c_int);
    (*sessions.offset(id as isize)).ptyfd = -(1 as libc::c_int);
    (*sessions.offset(id as isize)).ttyfd = -(1 as libc::c_int);
    (*sessions.offset(id as isize)).ptymaster = -(1 as libc::c_int);
    let ref mut fresh3 = (*sessions.offset(id as isize)).x11_chanids;
    *fresh3 = 0 as *mut libc::c_int;
    (*sessions.offset(id as isize)).next_unused = sessions_first_unused;
    sessions_first_unused = id;
}
pub unsafe extern "C" fn session_new() -> *mut Session {
    let mut s: *mut Session = 0 as *mut Session;
    let mut tmp: *mut Session = 0 as *mut Session;
    if sessions_first_unused == -(1 as libc::c_int) {
        if sessions_nalloc >= options.max_sessions {
            return 0 as *mut Session;
        }
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"session_new\0")).as_ptr(),
            1748 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"allocate (allocated %d max %d)\0" as *const u8 as *const libc::c_char,
            sessions_nalloc,
            options.max_sessions,
        );
        tmp = crate::xmalloc::xrecallocarray(
            sessions as *mut libc::c_void,
            sessions_nalloc as size_t,
            (sessions_nalloc + 1 as libc::c_int) as size_t,
            ::core::mem::size_of::<Session>() as libc::c_ulong,
        ) as *mut Session;
        if tmp.is_null() {
            crate::log::sshlog(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"session_new\0"))
                    .as_ptr(),
                1753 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"cannot allocate %d sessions\0" as *const u8 as *const libc::c_char,
                sessions_nalloc + 1 as libc::c_int,
            );
            return 0 as *mut Session;
        }
        sessions = tmp;
        let fresh4 = sessions_nalloc;
        sessions_nalloc = sessions_nalloc + 1;
        session_unused(fresh4);
    }
    if sessions_first_unused >= sessions_nalloc || sessions_first_unused < 0 as libc::c_int {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"session_new\0")).as_ptr(),
            1764 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"insane first_unused %d max %d nalloc %d\0" as *const u8 as *const libc::c_char,
            sessions_first_unused,
            options.max_sessions,
            sessions_nalloc,
        );
    }
    s = &mut *sessions.offset(sessions_first_unused as isize) as *mut Session;
    if (*s).used != 0 {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"session_new\0")).as_ptr(),
            1769 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"session %d already used\0" as *const u8 as *const libc::c_char,
            sessions_first_unused,
        );
    }
    sessions_first_unused = (*s).next_unused;
    (*s).used = 1 as libc::c_int;
    (*s).next_unused = -(1 as libc::c_int);
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"session_new\0")).as_ptr(),
        1773 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"session_new: session %d\0" as *const u8 as *const libc::c_char,
        (*s).self_0,
    );
    return s;
}
unsafe extern "C" fn session_dump() {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < sessions_nalloc {
        let mut s: *mut Session = &mut *sessions.offset(i as isize) as *mut Session;
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"session_dump\0")).as_ptr(),
            1791 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"dump: used %d next_unused %d session %d channel %d pid %ld\0" as *const u8
                as *const libc::c_char,
            (*s).used,
            (*s).next_unused,
            (*s).self_0,
            (*s).chanid,
            (*s).pid as libc::c_long,
        );
        i += 1;
        i;
    }
}
pub unsafe extern "C" fn session_open(
    mut authctxt: *mut Authctxt,
    mut chanid: libc::c_int,
) -> libc::c_int {
    let mut s: *mut Session = session_new();
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"session_open\0")).as_ptr(),
        1799 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"session_open: channel %d\0" as *const u8 as *const libc::c_char,
        chanid,
    );
    if s.is_null() {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"session_open\0")).as_ptr(),
            1801 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no more sessions\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    (*s).authctxt = authctxt;
    (*s).pw = (*authctxt).pw;
    if ((*s).pw).is_null() || (*authctxt).valid == 0 {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"session_open\0")).as_ptr(),
            1807 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no user for session %d\0" as *const u8 as *const libc::c_char,
            (*s).self_0,
        );
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"session_open\0")).as_ptr(),
        1808 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"session_open: session %d: link with channel %d\0" as *const u8 as *const libc::c_char,
        (*s).self_0,
        chanid,
    );
    (*s).chanid = chanid;
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn session_by_tty(mut tty: *mut libc::c_char) -> *mut Session {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < sessions_nalloc {
        let mut s: *mut Session = &mut *sessions.offset(i as isize) as *mut Session;
        if (*s).used != 0
            && (*s).ttyfd != -(1 as libc::c_int)
            && libc::strcmp(((*s).tty).as_mut_ptr(), tty) == 0 as libc::c_int
        {
            crate::log::sshlog(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"session_by_tty\0"))
                    .as_ptr(),
                1820 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"session_by_tty: session %d tty %s\0" as *const u8 as *const libc::c_char,
                i,
                tty,
            );
            return s;
        }
        i += 1;
        i;
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"session_by_tty\0")).as_ptr(),
        1824 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"session_by_tty: unknown tty %.100s\0" as *const u8 as *const libc::c_char,
        tty,
    );
    session_dump();
    return 0 as *mut Session;
}
unsafe extern "C" fn session_by_channel(mut id: libc::c_int) -> *mut Session {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < sessions_nalloc {
        let mut s: *mut Session = &mut *sessions.offset(i as isize) as *mut Session;
        if (*s).used != 0 && (*s).chanid == id {
            crate::log::sshlog(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"session_by_channel\0",
                ))
                .as_ptr(),
                1837 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"session_by_channel: session %d channel %d\0" as *const u8 as *const libc::c_char,
                i,
                id,
            );
            return s;
        }
        i += 1;
        i;
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"session_by_channel\0"))
            .as_ptr(),
        1841 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"session_by_channel: unknown channel %d\0" as *const u8 as *const libc::c_char,
        id,
    );
    session_dump();
    return 0 as *mut Session;
}
unsafe extern "C" fn session_by_x11_channel(mut id: libc::c_int) -> *mut Session {
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < sessions_nalloc {
        let mut s: *mut Session = &mut *sessions.offset(i as isize) as *mut Session;
        if !(((*s).x11_chanids).is_null() || (*s).used == 0) {
            j = 0 as libc::c_int;
            while *((*s).x11_chanids).offset(j as isize) != -(1 as libc::c_int) {
                if *((*s).x11_chanids).offset(j as isize) == id {
                    crate::log::sshlog(
                        b"session.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                            b"session_by_x11_channel\0",
                        ))
                        .as_ptr(),
                        1859 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"session_by_x11_channel: session %d channel %d\0" as *const u8
                            as *const libc::c_char,
                        (*s).self_0,
                        id,
                    );
                    return s;
                }
                j += 1;
                j;
            }
        }
        i += 1;
        i;
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"session_by_x11_channel\0"))
            .as_ptr(),
        1864 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"session_by_x11_channel: unknown channel %d\0" as *const u8 as *const libc::c_char,
        id,
    );
    session_dump();
    return 0 as *mut Session;
}
unsafe extern "C" fn session_by_pid(mut pid: pid_t) -> *mut Session {
    let mut i: libc::c_int = 0;
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"session_by_pid\0")).as_ptr(),
        1873 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"session_by_pid: pid %ld\0" as *const u8 as *const libc::c_char,
        pid as libc::c_long,
    );
    i = 0 as libc::c_int;
    while i < sessions_nalloc {
        let mut s: *mut Session = &mut *sessions.offset(i as isize) as *mut Session;
        if (*s).used != 0 && (*s).pid == pid {
            return s;
        }
        i += 1;
        i;
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"session_by_pid\0")).as_ptr(),
        1879 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"session_by_pid: unknown pid %ld\0" as *const u8 as *const libc::c_char,
        pid as libc::c_long,
    );
    session_dump();
    return 0 as *mut Session;
}
unsafe extern "C" fn session_window_change_req(
    mut ssh: *mut ssh,
    mut s: *mut Session,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = crate::packet::sshpkt_get_u32(ssh, &mut (*s).col);
    if r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_get_u32(ssh, &mut (*s).row);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_u32(ssh, &mut (*s).xpixel);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_u32(ssh, &mut (*s).ypixel);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }
    {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"session_window_change_req\0",
            ))
            .as_ptr(),
        );
    }
    pty_change_window_size((*s).ptyfd, (*s).row, (*s).col, (*s).xpixel, (*s).ypixel);
    return 1 as libc::c_int;
}
unsafe extern "C" fn session_pty_req(mut ssh: *mut ssh, mut s: *mut Session) -> libc::c_int {
    let mut r: libc::c_int = 0;
    if (*auth_opts).permit_pty_flag == 0 || options.permit_tty == 0 {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"session_pty_req\0"))
                .as_ptr(),
            1905 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Allocating a pty not permitted for this connection.\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if (*s).ttyfd != -(1 as libc::c_int) {
        crate::packet::ssh_packet_disconnect(
            ssh,
            b"Protocol error: you already have a pty.\0" as *const u8 as *const libc::c_char,
        );
    }
    r = crate::packet::sshpkt_get_cstring(ssh, &mut (*s).term, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_get_u32(ssh, &mut (*s).col);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_u32(ssh, &mut (*s).row);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_u32(ssh, &mut (*s).xpixel);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_u32(ssh, &mut (*s).ypixel);
            r != 0 as libc::c_int
        }
    {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"session_pty_req\0"))
                .as_ptr(),
        );
    }
    if libc::strcmp((*s).term, b"\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        libc::free((*s).term as *mut libc::c_void);
        (*s).term = 0 as *mut libc::c_char;
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"session_pty_req\0")).as_ptr(),
        1926 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Allocating pty.\0" as *const u8 as *const libc::c_char,
    );
    if if use_privsep != 0 {
        mm_pty_allocate(
            &mut (*s).ptyfd,
            &mut (*s).ttyfd,
            ((*s).tty).as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
        )
    } else {
        pty_allocate(
            &mut (*s).ptyfd,
            &mut (*s).ttyfd,
            ((*s).tty).as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
        )
    } == 0
    {
        libc::free((*s).term as *mut libc::c_void);
        (*s).term = 0 as *mut libc::c_char;
        (*s).ptyfd = -(1 as libc::c_int);
        (*s).ttyfd = -(1 as libc::c_int);
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"session_pty_req\0"))
                .as_ptr(),
            1933 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"session_pty_req: session %d alloc failed\0" as *const u8 as *const libc::c_char,
            (*s).self_0,
        );
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"session_pty_req\0")).as_ptr(),
        1936 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"session_pty_req: session %d alloc %s\0" as *const u8 as *const libc::c_char,
        (*s).self_0,
        ((*s).tty).as_mut_ptr(),
    );
    ssh_tty_parse_modes(ssh, (*s).ttyfd);
    r = crate::packet::sshpkt_get_end(ssh);
    if r != 0 as libc::c_int {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"session_pty_req\0"))
                .as_ptr(),
        );
    }
    if use_privsep == 0 {
        pty_setowner((*s).pw, ((*s).tty).as_mut_ptr());
    }
    pty_change_window_size((*s).ptyfd, (*s).row, (*s).col, (*s).xpixel, (*s).ypixel);
    session_proctitle(s);
    return 1 as libc::c_int;
}
unsafe extern "C" fn session_subsystem_req(mut ssh: *mut ssh, mut s: *mut Session) -> libc::c_int {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut prog: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cmd: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut type_0: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: u_int = 0;
    r = crate::packet::sshpkt_get_cstring(ssh, &mut (*s).subsys, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = crate::packet::sshpkt_get_end(ssh);
        r != 0 as libc::c_int
    } {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"session_subsystem_req\0"))
                .as_ptr(),
        );
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"session_subsystem_req\0"))
            .as_ptr(),
        1965 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"subsystem request for %.100s by user %s\0" as *const u8 as *const libc::c_char,
        (*s).subsys,
        (*(*s).pw).pw_name,
    );
    i = 0 as libc::c_int as u_int;
    while i < options.num_subsystems {
        if libc::strcmp((*s).subsys, options.subsystem_name[i as usize]) == 0 as libc::c_int {
            prog = options.subsystem_command[i as usize];
            cmd = options.subsystem_args[i as usize];
            if libc::strcmp(b"internal-sftp\0" as *const u8 as *const libc::c_char, prog)
                == 0 as libc::c_int
            {
                (*s).is_subsystem = 2 as libc::c_int;
                crate::log::sshlog(
                    b"session.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"session_subsystem_req\0",
                    ))
                    .as_ptr(),
                    1973 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"subsystem: %s\0" as *const u8 as *const libc::c_char,
                    prog,
                );
            } else {
                if libc::stat(prog, &mut st) == -(1 as libc::c_int) {
                    crate::log::sshlog(
                        b"session.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                            b"session_subsystem_req\0",
                        ))
                        .as_ptr(),
                        1977 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"subsystem: cannot libc::stat %s: %s\0" as *const u8
                            as *const libc::c_char,
                        prog,
                        libc::strerror(*libc::__errno_location()),
                    );
                }
                (*s).is_subsystem = 1 as libc::c_int;
                crate::log::sshlog(
                    b"session.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"session_subsystem_req\0",
                    ))
                    .as_ptr(),
                    1979 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"subsystem: exec() %s\0" as *const u8 as *const libc::c_char,
                    cmd,
                );
            }
            crate::xmalloc::xasprintf(
                &mut type_0 as *mut *mut libc::c_char,
                b"session:subsystem:%s\0" as *const u8 as *const libc::c_char,
                options.subsystem_name[i as usize],
            );
            channel_set_xtype(ssh, (*s).chanid, type_0);
            libc::free(type_0 as *mut libc::c_void);
            success = (do_exec(ssh, s, cmd) == 0 as libc::c_int) as libc::c_int;
            break;
        } else {
            i = i.wrapping_add(1);
            i;
        }
    }
    if success == 0 {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"session_subsystem_req\0"))
                .as_ptr(),
            1992 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"subsystem request for %.100s by user %s failed, subsystem not found\0" as *const u8
                as *const libc::c_char,
            (*s).subsys,
            (*(*s).pw).pw_name,
        );
    }
    return success;
}
unsafe extern "C" fn session_x11_req(mut ssh: *mut ssh, mut s: *mut Session) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0;
    let mut single_connection: u_char = 0 as libc::c_int as u_char;
    if !((*s).auth_proto).is_null() || !((*s).auth_data).is_null() {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"session_x11_req\0"))
                .as_ptr(),
            2005 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"session_x11_req: session %d: x11 forwarding already active\0" as *const u8
                as *const libc::c_char,
            (*s).self_0,
        );
        return 0 as libc::c_int;
    }
    r = crate::packet::sshpkt_get_u8(ssh, &mut single_connection);
    if r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_get_cstring(ssh, &mut (*s).auth_proto, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_cstring(ssh, &mut (*s).auth_data, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_u32(ssh, &mut (*s).screen);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }
    {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"session_x11_req\0"))
                .as_ptr(),
        );
    }
    (*s).single_connection = single_connection as libc::c_int;
    if xauth_valid_string((*s).auth_proto) != 0 && xauth_valid_string((*s).auth_data) != 0 {
        success = session_setup_x11fwd(ssh, s);
    } else {
        success = 0 as libc::c_int;
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"session_x11_req\0"))
                .as_ptr(),
            2022 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Invalid X11 forwarding data\0" as *const u8 as *const libc::c_char,
        );
    }
    if success == 0 {
        libc::free((*s).auth_proto as *mut libc::c_void);
        libc::free((*s).auth_data as *mut libc::c_void);
        (*s).auth_proto = 0 as *mut libc::c_char;
        (*s).auth_data = 0 as *mut libc::c_char;
    }
    return success;
}
unsafe extern "C" fn session_shell_req(mut ssh: *mut ssh, mut s: *mut Session) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = crate::packet::sshpkt_get_end(ssh);
    if r != 0 as libc::c_int {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"session_shell_req\0"))
                .as_ptr(),
        );
    }
    channel_set_xtype(
        ssh,
        (*s).chanid,
        b"session:shell\0" as *const u8 as *const libc::c_char,
    );
    return (do_exec(ssh, s, 0 as *const libc::c_char) == 0 as libc::c_int) as libc::c_int;
}
unsafe extern "C" fn session_exec_req(mut ssh: *mut ssh, mut s: *mut Session) -> libc::c_int {
    let mut success: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut command: *mut libc::c_char = 0 as *mut libc::c_char;
    r = crate::packet::sshpkt_get_cstring(ssh, &mut command, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = crate::packet::sshpkt_get_end(ssh);
        r != 0 as libc::c_int
    } {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"session_exec_req\0"))
                .as_ptr(),
        );
    }
    channel_set_xtype(
        ssh,
        (*s).chanid,
        b"session:command\0" as *const u8 as *const libc::c_char,
    );
    success = (do_exec(ssh, s, command) == 0 as libc::c_int) as libc::c_int as u_int;
    libc::free(command as *mut libc::c_void);
    return success as libc::c_int;
}
unsafe extern "C" fn session_break_req(mut ssh: *mut ssh, mut s: *mut Session) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = crate::packet::sshpkt_get_u32(ssh, 0 as *mut u_int32_t);
    if r != 0 as libc::c_int || {
        r = crate::packet::sshpkt_get_end(ssh);
        r != 0 as libc::c_int
    } {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"session_break_req\0"))
                .as_ptr(),
        );
    }
    if (*s).ptymaster == -(1 as libc::c_int)
        || tcsendbreak((*s).ptymaster, 0 as libc::c_int) == -(1 as libc::c_int)
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn session_env_req(mut ssh: *mut ssh, mut s: *mut Session) -> libc::c_int {
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut val: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: u_int = 0;
    let mut r: libc::c_int = 0;
    r = crate::packet::sshpkt_get_cstring(ssh, &mut name, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = crate::packet::sshpkt_get_cstring(ssh, &mut val, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = crate::packet::sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }
    {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"session_env_req\0"))
                .as_ptr(),
        );
    }
    if (*s).num_env > 128 as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"session_env_req\0"))
                .as_ptr(),
            2092 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"Ignoring env request %s: too many env vars\0" as *const u8 as *const libc::c_char,
            name,
        );
    } else {
        i = 0 as libc::c_int as u_int;
        while i < options.num_accept_env {
            if match_pattern(name, *(options.accept_env).offset(i as isize)) != 0 {
                crate::log::sshlog(
                    b"session.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"session_env_req\0",
                    ))
                    .as_ptr(),
                    2098 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG2,
                    0 as *const libc::c_char,
                    b"Setting env %d: %s=%s\0" as *const u8 as *const libc::c_char,
                    (*s).num_env,
                    name,
                    val,
                );
                (*s).env = crate::xmalloc::xrecallocarray(
                    (*s).env as *mut libc::c_void,
                    (*s).num_env as size_t,
                    ((*s).num_env).wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
                    ::core::mem::size_of::<C2RustUnnamed_5>() as libc::c_ulong,
                ) as *mut C2RustUnnamed_5;
                let ref mut fresh5 = (*((*s).env).offset((*s).num_env as isize)).name;
                *fresh5 = name;
                let ref mut fresh6 = (*((*s).env).offset((*s).num_env as isize)).val;
                *fresh6 = val;
                (*s).num_env = ((*s).num_env).wrapping_add(1);
                (*s).num_env;
                return 1 as libc::c_int;
            }
            i = i.wrapping_add(1);
            i;
        }
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"session_env_req\0"))
                .as_ptr(),
            2107 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"Ignoring env request %s: disallowed name\0" as *const u8 as *const libc::c_char,
            name,
        );
    }
    libc::free(name as *mut libc::c_void);
    libc::free(val as *mut libc::c_void);
    return 0 as libc::c_int;
}
unsafe extern "C" fn name2sig(mut name: *mut libc::c_char) -> libc::c_int {
    if libc::strcmp(name, b"HUP\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 1 as libc::c_int;
    }
    if libc::strcmp(name, b"INT\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 2 as libc::c_int;
    }
    if libc::strcmp(name, b"KILL\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 9 as libc::c_int;
    }
    if libc::strcmp(name, b"QUIT\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 3 as libc::c_int;
    }
    if libc::strcmp(name, b"TERM\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 15 as libc::c_int;
    }
    if libc::strcmp(name, b"USR1\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 10 as libc::c_int;
    }
    if libc::strcmp(name, b"USR2\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return 12 as libc::c_int;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn session_signal_req(mut ssh: *mut ssh, mut s: *mut Session) -> libc::c_int {
    let mut signame: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut sig: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    r = crate::packet::sshpkt_get_cstring(ssh, &mut signame, 0 as *mut size_t);
    if r != 0 as libc::c_int || {
        r = crate::packet::sshpkt_get_end(ssh);
        r != 0 as libc::c_int
    } {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"session_signal_req\0"))
                .as_ptr(),
            2147 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"parse\0" as *const u8 as *const libc::c_char,
        );
    } else {
        sig = name2sig(signame);
        if sig == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"session_signal_req\0",
                ))
                .as_ptr(),
                2151 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"unsupported signal \"%s\"\0" as *const u8 as *const libc::c_char,
                signame,
            );
        } else if (*s).pid <= 0 as libc::c_int {
            crate::log::sshlog(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"session_signal_req\0",
                ))
                .as_ptr(),
                2155 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"no pid for session %d\0" as *const u8 as *const libc::c_char,
                (*s).self_0,
            );
        } else if (*s).forced != 0 || (*s).is_subsystem != 0 {
            crate::log::sshlog(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"session_signal_req\0",
                ))
                .as_ptr(),
                2160 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"refusing to send signal %s to %s session\0" as *const u8 as *const libc::c_char,
                signame,
                if (*s).forced != 0 {
                    b"forced-command\0" as *const u8 as *const libc::c_char
                } else {
                    b"subsystem\0" as *const u8 as *const libc::c_char
                },
            );
        } else if use_privsep == 0 || mm_is_monitor() != 0 {
            crate::log::sshlog(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"session_signal_req\0",
                ))
                .as_ptr(),
                2164 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"session signalling requires privilege separation\0" as *const u8
                    as *const libc::c_char,
            );
        } else {
            crate::log::sshlog(
                b"session.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"session_signal_req\0",
                ))
                .as_ptr(),
                2168 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"signal %s, killpg(%ld, %d)\0" as *const u8 as *const libc::c_char,
                signame,
                (*s).pid as libc::c_long,
                sig,
            );
            temporarily_use_uid((*s).pw);
            r = killpg((*s).pid, sig);
            restore_uid();
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"session.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"session_signal_req\0",
                    ))
                    .as_ptr(),
                    2174 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"killpg(%ld, %d): %s\0" as *const u8 as *const libc::c_char,
                    (*s).pid as libc::c_long,
                    sig,
                    libc::strerror(*libc::__errno_location()),
                );
            } else {
                success = 1 as libc::c_int;
            }
        }
    }
    libc::free(signame as *mut libc::c_void);
    return success;
}
unsafe extern "C" fn session_auth_agent_req(mut ssh: *mut ssh, mut s: *mut Session) -> libc::c_int {
    static mut called: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    r = crate::packet::sshpkt_get_end(ssh);
    if r != 0 as libc::c_int {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: parse packet\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"session_auth_agent_req\0",
            ))
            .as_ptr(),
        );
    }
    if (*auth_opts).permit_agent_forwarding_flag == 0 || options.allow_agent_forwarding == 0 {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"session_auth_agent_req\0",
            ))
            .as_ptr(),
            2195 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"agent forwarding disabled\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if called != 0 {
        return 0 as libc::c_int;
    } else {
        called = 1 as libc::c_int;
        return auth_input_request_forwarding(ssh, (*s).pw);
    };
}
pub unsafe extern "C" fn session_input_channel_req(
    mut ssh: *mut ssh,
    mut c: *mut Channel,
    mut rtype: *const libc::c_char,
) -> libc::c_int {
    let mut success: libc::c_int = 0 as libc::c_int;
    let mut s: *mut Session = 0 as *mut Session;
    s = session_by_channel((*c).self_0);
    if s.is_null() {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"session_input_channel_req\0",
            ))
            .as_ptr(),
            2213 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"no session %d req %.100s\0" as *const u8 as *const libc::c_char,
            (*c).self_0,
            rtype,
        );
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"session_input_channel_req\0"))
            .as_ptr(),
        2216 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"session %d req %s\0" as *const u8 as *const libc::c_char,
        (*s).self_0,
        rtype,
    );
    if (*c).type_0 == 10 as libc::c_int {
        if libc::strcmp(rtype, b"shell\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
            success = session_shell_req(ssh, s);
        } else if libc::strcmp(rtype, b"exec\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            success = session_exec_req(ssh, s);
        } else if libc::strcmp(rtype, b"pty-req\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            success = session_pty_req(ssh, s);
        } else if libc::strcmp(rtype, b"x11-req\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            success = session_x11_req(ssh, s);
        } else if libc::strcmp(
            rtype,
            b"auth-agent-req@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            success = session_auth_agent_req(ssh, s);
        } else if libc::strcmp(rtype, b"subsystem\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            success = session_subsystem_req(ssh, s);
        } else if libc::strcmp(rtype, b"env\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            success = session_env_req(ssh, s);
        }
    }
    if libc::strcmp(
        rtype,
        b"window-change\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        success = session_window_change_req(ssh, s);
    } else if libc::strcmp(rtype, b"break\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        success = session_break_req(ssh, s);
    } else if libc::strcmp(rtype, b"signal\0" as *const u8 as *const libc::c_char)
        == 0 as libc::c_int
    {
        success = session_signal_req(ssh, s);
    }
    return success;
}
pub unsafe extern "C" fn session_set_fds(
    mut ssh: *mut ssh,
    mut s: *mut Session,
    mut fdin: libc::c_int,
    mut fdout: libc::c_int,
    mut fderr: libc::c_int,
    mut ignore_fderr: libc::c_int,
    mut is_tty: libc::c_int,
) {
    if (*s).chanid == -(1 as libc::c_int) {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"session_set_fds\0"))
                .as_ptr(),
            2259 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no channel for session %d\0" as *const u8 as *const libc::c_char,
            (*s).self_0,
        );
    }
    channel_set_fds(
        ssh,
        (*s).chanid,
        fdout,
        fdin,
        fderr,
        if ignore_fderr != 0 {
            0 as libc::c_int
        } else {
            1 as libc::c_int
        },
        1 as libc::c_int,
        is_tty,
        (64 as libc::c_int * (32 as libc::c_int * 1024 as libc::c_int)) as u_int,
    );
}
pub unsafe extern "C" fn session_pty_cleanup2(mut s: *mut Session) {
    if s.is_null() {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"session_pty_cleanup2\0"))
                .as_ptr(),
            2274 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no session\0" as *const u8 as *const libc::c_char,
        );
        return;
    }
    if (*s).ttyfd == -(1 as libc::c_int) {
        return;
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"session_pty_cleanup2\0"))
            .as_ptr(),
        2280 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"session %d release %s\0" as *const u8 as *const libc::c_char,
        (*s).self_0,
        ((*s).tty).as_mut_ptr(),
    );
    if (*s).pid != 0 as libc::c_int {
        record_logout((*s).pid, ((*s).tty).as_mut_ptr(), (*(*s).pw).pw_name);
    }
    if libc::getuid() == 0 as libc::c_int as libc::c_uint {
        pty_release(((*s).tty).as_mut_ptr());
    }
    if (*s).ptymaster != -(1 as libc::c_int) && close((*s).ptymaster) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"session_pty_cleanup2\0"))
                .as_ptr(),
            2297 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"close(s->ptymaster/%d): %s\0" as *const u8 as *const libc::c_char,
            (*s).ptymaster,
            libc::strerror(*libc::__errno_location()),
        );
    }
    (*s).ttyfd = -(1 as libc::c_int);
}
pub unsafe extern "C" fn session_pty_cleanup(mut s: *mut Session) {
    if use_privsep != 0 {
        mm_session_pty_cleanup2(s);
    } else {
        session_pty_cleanup2(s);
    };
}
unsafe extern "C" fn sig2name(mut sig: libc::c_int) -> *mut libc::c_char {
    if sig == 6 as libc::c_int {
        return b"ABRT\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if sig == 14 as libc::c_int {
        return b"ALRM\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if sig == 8 as libc::c_int {
        return b"FPE\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if sig == 1 as libc::c_int {
        return b"HUP\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if sig == 4 as libc::c_int {
        return b"ILL\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if sig == 2 as libc::c_int {
        return b"INT\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if sig == 9 as libc::c_int {
        return b"KILL\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if sig == 13 as libc::c_int {
        return b"PIPE\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if sig == 3 as libc::c_int {
        return b"QUIT\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if sig == 11 as libc::c_int {
        return b"SEGV\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if sig == 15 as libc::c_int {
        return b"TERM\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if sig == 10 as libc::c_int {
        return b"USR1\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if sig == 12 as libc::c_int {
        return b"USR2\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    return b"SIG@openssh.com\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
}
unsafe extern "C" fn session_close_x11(mut ssh: *mut ssh, mut id: libc::c_int) {
    let mut c: *mut Channel = 0 as *mut Channel;
    c = channel_by_id(ssh, id);
    if c.is_null() {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"session_close_x11\0"))
                .as_ptr(),
            2336 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"x11 channel %d missing\0" as *const u8 as *const libc::c_char,
            id,
        );
    } else {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"session_close_x11\0"))
                .as_ptr(),
            2339 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"detach x11 channel %d\0" as *const u8 as *const libc::c_char,
            id,
        );
        channel_cancel_cleanup(ssh, id);
        if (*c).ostate != 3 as libc::c_int as libc::c_uint {
            chan_mark_dead(ssh, c);
        }
    };
}
unsafe extern "C" fn session_close_single_x11(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut _force: libc::c_int,
    mut _arg: *mut libc::c_void,
) {
    let mut s: *mut Session = 0 as *mut Session;
    let mut i: u_int = 0;
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"session_close_single_x11\0"))
            .as_ptr(),
        2352 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"channel %d\0" as *const u8 as *const libc::c_char,
        id,
    );
    channel_cancel_cleanup(ssh, id);
    s = session_by_x11_channel(id);
    if s.is_null() {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"session_close_single_x11\0",
            ))
            .as_ptr(),
            2355 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no x11 channel %d\0" as *const u8 as *const libc::c_char,
            id,
        );
    }
    i = 0 as libc::c_int as u_int;
    while *((*s).x11_chanids).offset(i as isize) != -(1 as libc::c_int) {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"session_close_single_x11\0",
            ))
            .as_ptr(),
            2358 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"session %d: closing channel %d\0" as *const u8 as *const libc::c_char,
            (*s).self_0,
            *((*s).x11_chanids).offset(i as isize),
        );
        if *((*s).x11_chanids).offset(i as isize) != id {
            session_close_x11(ssh, *((*s).x11_chanids).offset(i as isize));
        }
        i = i.wrapping_add(1);
        i;
    }
    libc::free((*s).x11_chanids as *mut libc::c_void);
    (*s).x11_chanids = 0 as *mut libc::c_int;
    libc::free((*s).display as *mut libc::c_void);
    (*s).display = 0 as *mut libc::c_char;
    libc::free((*s).auth_proto as *mut libc::c_void);
    (*s).auth_proto = 0 as *mut libc::c_char;
    libc::free((*s).auth_data as *mut libc::c_void);
    (*s).auth_data = 0 as *mut libc::c_char;
    libc::free((*s).auth_display as *mut libc::c_void);
    (*s).auth_display = 0 as *mut libc::c_char;
}
unsafe extern "C" fn session_exit_message(
    mut ssh: *mut ssh,
    mut s: *mut Session,
    mut status: libc::c_int,
) {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut r: libc::c_int = 0;
    c = channel_lookup(ssh, (*s).chanid);
    if c.is_null() {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"session_exit_message\0"))
                .as_ptr(),
            2385 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"session %d: no channel %d\0" as *const u8 as *const libc::c_char,
            (*s).self_0,
            (*s).chanid,
        );
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"session_exit_message\0"))
            .as_ptr(),
        2387 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"session %d channel %d pid %ld\0" as *const u8 as *const libc::c_char,
        (*s).self_0,
        (*s).chanid,
        (*s).pid as libc::c_long,
    );
    if status & 0x7f as libc::c_int == 0 as libc::c_int {
        channel_request_start(
            ssh,
            (*s).chanid,
            b"libc::exit-status\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            0 as libc::c_int,
        );
        r = crate::packet::sshpkt_put_u32(
            ssh,
            ((status & 0xff00 as libc::c_int) >> 8 as libc::c_int) as u_int32_t,
        );
        if r != 0 as libc::c_int || {
            r = crate::packet::sshpkt_send(ssh);
            r != 0 as libc::c_int
        } {
            sshpkt_fatal(
                ssh,
                r,
                b"%s: libc::exit reply\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"session_exit_message\0",
                ))
                .as_ptr(),
            );
        }
    } else if ((status & 0x7f as libc::c_int) + 1 as libc::c_int) as libc::c_schar as libc::c_int
        >> 1 as libc::c_int
        > 0 as libc::c_int
    {
        channel_request_start(
            ssh,
            (*s).chanid,
            b"libc::exit-signal\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            0 as libc::c_int,
        );
        r = crate::packet::sshpkt_put_cstring(
            ssh,
            sig2name(status & 0x7f as libc::c_int) as *const libc::c_void,
        );
        if r != 0 as libc::c_int
            || {
                r = crate::packet::sshpkt_put_u8(
                    ssh,
                    (if status & 0x80 as libc::c_int != 0 {
                        1 as libc::c_int
                    } else {
                        0 as libc::c_int
                    }) as u_char,
                );
                r != 0 as libc::c_int
            }
            || {
                r = crate::packet::sshpkt_put_cstring(
                    ssh,
                    b"\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                );
                r != 0 as libc::c_int
            }
            || {
                r = crate::packet::sshpkt_put_cstring(
                    ssh,
                    b"\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                );
                r != 0 as libc::c_int
            }
            || {
                r = crate::packet::sshpkt_send(ssh);
                r != 0 as libc::c_int
            }
        {
            sshpkt_fatal(
                ssh,
                r,
                b"%s: libc::exit reply\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"session_exit_message\0",
                ))
                .as_ptr(),
            );
        }
    } else {
        crate::packet::ssh_packet_disconnect(
            ssh,
            b"wait returned status %04x.\0" as *const u8 as *const libc::c_char,
            status,
        );
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"session_exit_message\0"))
            .as_ptr(),
        2411 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"release channel %d\0" as *const u8 as *const libc::c_char,
        (*s).chanid,
    );
    channel_register_cleanup(
        ssh,
        (*c).self_0,
        Some(
            session_close_by_channel
                as unsafe extern "C" fn(
                    *mut ssh,
                    libc::c_int,
                    libc::c_int,
                    *mut libc::c_void,
                ) -> (),
        ),
        1 as libc::c_int,
    );
    if (*c).ostate != 3 as libc::c_int as libc::c_uint {
        chan_write_failed(ssh, c);
    }
}
pub unsafe extern "C" fn session_close(mut ssh: *mut ssh, mut s: *mut Session) {
    let mut i: u_int = 0;
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"session_close\0")).as_ptr(),
        2439 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_VERBOSE,
        0 as *const libc::c_char,
        b"Close session: user %s from %.200s port %d id %d\0" as *const u8 as *const libc::c_char,
        (*(*s).pw).pw_name,
        ssh_remote_ipaddr(ssh),
        ssh_remote_port(ssh),
        (*s).self_0,
    );
    if (*s).ttyfd != -(1 as libc::c_int) {
        session_pty_cleanup(s);
    }
    libc::free((*s).term as *mut libc::c_void);
    libc::free((*s).display as *mut libc::c_void);
    libc::free((*s).x11_chanids as *mut libc::c_void);
    libc::free((*s).auth_display as *mut libc::c_void);
    libc::free((*s).auth_data as *mut libc::c_void);
    libc::free((*s).auth_proto as *mut libc::c_void);
    libc::free((*s).subsys as *mut libc::c_void);
    if !((*s).env).is_null() {
        i = 0 as libc::c_int as u_int;
        while i < (*s).num_env {
            libc::free((*((*s).env).offset(i as isize)).name as *mut libc::c_void);
            libc::free((*((*s).env).offset(i as isize)).val as *mut libc::c_void);
            i = i.wrapping_add(1);
            i;
        }
        libc::free((*s).env as *mut libc::c_void);
    }
    session_proctitle(s);
    session_unused((*s).self_0);
}
pub unsafe extern "C" fn session_close_by_pid(
    mut ssh: *mut ssh,
    mut pid: pid_t,
    mut status: libc::c_int,
) {
    let mut s: *mut Session = session_by_pid(pid);
    if s.is_null() {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"session_close_by_pid\0"))
                .as_ptr(),
            2466 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"no session for pid %ld\0" as *const u8 as *const libc::c_char,
            pid as libc::c_long,
        );
        return;
    }
    if (*s).chanid != -(1 as libc::c_int) {
        session_exit_message(ssh, s, status);
    }
    if (*s).ttyfd != -(1 as libc::c_int) {
        session_pty_cleanup(s);
    }
    (*s).pid = 0 as libc::c_int;
}
pub unsafe extern "C" fn session_close_by_channel(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut force: libc::c_int,
    mut _arg: *mut libc::c_void,
) {
    let mut s: *mut Session = session_by_channel(id);
    let mut i: u_int = 0;
    if s.is_null() {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"session_close_by_channel\0",
            ))
            .as_ptr(),
            2487 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"no session for id %d\0" as *const u8 as *const libc::c_char,
            id,
        );
        return;
    }
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"session_close_by_channel\0"))
            .as_ptr(),
        2490 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"channel %d child %ld\0" as *const u8 as *const libc::c_char,
        id,
        (*s).pid as libc::c_long,
    );
    if (*s).pid != 0 as libc::c_int {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"session_close_by_channel\0",
            ))
            .as_ptr(),
            2492 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"channel %d: has child, ttyfd %d\0" as *const u8 as *const libc::c_char,
            id,
            (*s).ttyfd,
        );
        if (*s).ttyfd != -(1 as libc::c_int) {
            session_pty_cleanup(s);
        }
        if force == 0 {
            return;
        }
    }
    channel_cancel_cleanup(ssh, (*s).chanid);
    if !((*s).x11_chanids).is_null() {
        i = 0 as libc::c_int as u_int;
        while *((*s).x11_chanids).offset(i as isize) != -(1 as libc::c_int) {
            session_close_x11(ssh, *((*s).x11_chanids).offset(i as isize));
            *((*s).x11_chanids).offset(i as isize) = -(1 as libc::c_int);
            i = i.wrapping_add(1);
            i;
        }
    }
    (*s).chanid = -(1 as libc::c_int);
    session_close(ssh, s);
}
pub unsafe extern "C" fn session_destroy_all(
    mut ssh: *mut ssh,
    mut closefunc: Option<unsafe extern "C" fn(*mut Session) -> ()>,
) {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < sessions_nalloc {
        let mut s: *mut Session = &mut *sessions.offset(i as isize) as *mut Session;
        if (*s).used != 0 {
            if closefunc.is_some() {
                closefunc.expect("non-null function pointer")(s);
            } else {
                session_close(ssh, s);
            }
        }
        i += 1;
        i;
    }
}
unsafe extern "C" fn session_tty_list() -> *mut libc::c_char {
    static mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut i: libc::c_int = 0;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    buf[0 as libc::c_int as usize] = '\0' as i32 as libc::c_char;
    i = 0 as libc::c_int;
    while i < sessions_nalloc {
        let mut s: *mut Session = &mut *sessions.offset(i as isize) as *mut Session;
        if (*s).used != 0 && (*s).ttyfd != -(1 as libc::c_int) {
            if strncmp(
                ((*s).tty).as_mut_ptr(),
                b"/dev/\0" as *const u8 as *const libc::c_char,
                5 as libc::c_int as libc::c_ulong,
            ) != 0 as libc::c_int
            {
                cp = libc::strrchr(((*s).tty).as_mut_ptr(), '/' as i32);
                cp = if cp.is_null() {
                    ((*s).tty).as_mut_ptr()
                } else {
                    cp.offset(1 as libc::c_int as isize)
                };
            } else {
                cp = ((*s).tty).as_mut_ptr().offset(5 as libc::c_int as isize);
            }
            if buf[0 as libc::c_int as usize] as libc::c_int != '\0' as i32 {
                strlcat(
                    buf.as_mut_ptr(),
                    b",\0" as *const u8 as *const libc::c_char,
                    ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
                );
            }
            strlcat(
                buf.as_mut_ptr(),
                cp,
                ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
            );
        }
        i += 1;
        i;
    }
    if buf[0 as libc::c_int as usize] as libc::c_int == '\0' as i32 {
        strlcpy(
            buf.as_mut_ptr(),
            b"notty\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        );
    }
    return buf.as_mut_ptr();
}
pub unsafe extern "C" fn session_proctitle(mut s: *mut Session) {
    if ((*s).pw).is_null() {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"session_proctitle\0"))
                .as_ptr(),
            2565 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no user for session %d\0" as *const u8 as *const libc::c_char,
            (*s).self_0,
        );
    } else {
        setproctitle(
            b"%s@%s\0" as *const u8 as *const libc::c_char,
            (*(*s).pw).pw_name,
            session_tty_list(),
        );
    };
}
pub unsafe extern "C" fn session_setup_x11fwd(
    mut ssh: *mut ssh,
    mut s: *mut Session,
) -> libc::c_int {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut display: [libc::c_char; 512] = [0; 512];
    let mut auth_display: [libc::c_char; 512] = [0; 512];
    let mut hostname: [libc::c_char; 1025] = [0; 1025];
    let mut i: u_int = 0;
    if (*auth_opts).permit_x11_forwarding_flag == 0 {
        ssh_packet_send_debug(
            ssh,
            b"X11 forwarding disabled by key options.\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if options.x11_forwarding == 0 {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"session_setup_x11fwd\0"))
                .as_ptr(),
            2583 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"X11 forwarding disabled in server configuration file.\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if (options.xauth_location).is_null()
        || libc::stat(options.xauth_location, &mut st) == -(1 as libc::c_int)
    {
        ssh_packet_send_debug(
            ssh,
            b"No xauth program; cannot forward X11.\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if !((*s).display).is_null() {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"session_setup_x11fwd\0"))
                .as_ptr(),
            2592 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"X11 display already set.\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if x11_create_display_inet(
        ssh,
        options.x11_display_offset,
        options.x11_use_localhost,
        (*s).single_connection,
        &mut (*s).display_number,
        &mut (*s).x11_chanids,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"session_setup_x11fwd\0"))
                .as_ptr(),
            2598 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"x11_create_display_inet failed.\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as u_int;
    while *((*s).x11_chanids).offset(i as isize) != -(1 as libc::c_int) {
        channel_register_cleanup(
            ssh,
            *((*s).x11_chanids).offset(i as isize),
            Some(
                session_close_single_x11
                    as unsafe extern "C" fn(
                        *mut ssh,
                        libc::c_int,
                        libc::c_int,
                        *mut libc::c_void,
                    ) -> (),
            ),
            0 as libc::c_int,
        );
        i = i.wrapping_add(1);
        i;
    }
    if gethostname(
        hostname.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"session.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"session_setup_x11fwd\0"))
                .as_ptr(),
            2608 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"gethostname: %.100s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    if options.x11_use_localhost != 0 {
        libc::snprintf(
            display.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 512]>() as usize,
            b"localhost:%u.%u\0" as *const u8 as *const libc::c_char,
            (*s).display_number,
            (*s).screen,
        );
        libc::snprintf(
            auth_display.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 512]>() as usize,
            b"unix:%u.%u\0" as *const u8 as *const libc::c_char,
            (*s).display_number,
            (*s).screen,
        );
        (*s).display = crate::xmalloc::xstrdup(display.as_mut_ptr());
        (*s).auth_display = crate::xmalloc::xstrdup(auth_display.as_mut_ptr());
    } else {
        libc::snprintf(
            display.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 512]>() as usize,
            b"%.400s:%u.%u\0" as *const u8 as *const libc::c_char,
            hostname.as_mut_ptr(),
            (*s).display_number,
            (*s).screen,
        );
        (*s).display = crate::xmalloc::xstrdup(display.as_mut_ptr());
        (*s).auth_display = crate::xmalloc::xstrdup(display.as_mut_ptr());
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn do_authenticated2(mut ssh: *mut ssh, mut authctxt: *mut Authctxt) {
    server_loop2(ssh, authctxt);
}
pub unsafe extern "C" fn do_cleanup(mut ssh: *mut ssh, mut authctxt: *mut Authctxt) {
    static mut called: libc::c_int = 0 as libc::c_int;
    crate::log::sshlog(
        b"session.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"do_cleanup\0")).as_ptr(),
        2657 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"do_cleanup\0" as *const u8 as *const libc::c_char,
    );
    if is_child != 0 {
        return;
    }
    if called != 0 {
        return;
    }
    called = 1 as libc::c_int;
    if authctxt.is_null() {
        return;
    }
    if (*authctxt).authenticated == 0 {
        return;
    }
    auth_sock_cleanup_proc((*authctxt).pw);
    if !auth_info_file.is_null() {
        temporarily_use_uid((*authctxt).pw);
        unlink(auth_info_file);
        restore_uid();
        libc::free(auth_info_file as *mut libc::c_void);
        auth_info_file = 0 as *mut libc::c_char;
    }
    if use_privsep == 0 || mm_is_monitor() != 0 {
        session_destroy_all(
            ssh,
            Some(session_pty_cleanup2 as unsafe extern "C" fn(*mut Session) -> ()),
        );
    }
}
pub unsafe extern "C" fn session_get_remote_name_or_ip(
    mut ssh: *mut ssh,
    mut utmp_size: u_int,
    mut use_dns: libc::c_int,
) -> *const libc::c_char {
    let mut remote: *const libc::c_char = b"\0" as *const u8 as *const libc::c_char;
    if utmp_size > 0 as libc::c_int as libc::c_uint {
        remote = auth_get_canonical_hostname(ssh, use_dns);
    }
    if utmp_size == 0 as libc::c_int as libc::c_uint || strlen(remote) > utmp_size as libc::c_ulong
    {
        remote = ssh_remote_ipaddr(ssh);
    }
    return remote;
}
