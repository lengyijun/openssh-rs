use crate::atomicio::atomicio;
use ::libc;
use libc::kill;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type ssh_channels;

    pub type ec_key_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_group_st;
    pub type dh_st;
    pub type umac_ctx;
    pub type ssh_hmac_ctx;
    pub type sshcipher;
    pub type session_state;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn sys_tun_outfilter(
        _: *mut ssh,
        _: *mut Channel,
        _: *mut *mut u_char,
        _: *mut size_t,
    ) -> *mut u_char;
    fn sys_tun_infilter(
        _: *mut ssh,
        _: *mut Channel,
        _: *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn arc4random_buf(_: *mut libc::c_void, _: size_t);
    fn poll(__fds: *mut pollfd, __nfds: nfds_t, __timeout: libc::c_int) -> libc::c_int;

    fn setproctitle(fmt: *const libc::c_char, _: ...);
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    static mut stdout: *mut libc::FILE;
    static mut stderr: *mut libc::FILE;

    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn fgets(
        __s: *mut libc::c_char,
        __n: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> *mut libc::c_char;
    fn fileno(__stream: *mut libc::FILE) -> libc::c_int;
    fn pclose(__stream: *mut libc::FILE) -> libc::c_int;
    fn popen(__command: *const libc::c_char, __modes: *const libc::c_char) -> *mut libc::FILE;
    fn rmdir(__path: *const libc::c_char) -> libc::c_int;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn unlink(__name: *const libc::c_char) -> libc::c_int;

    fn ioctl(__fd: libc::c_int, __request: libc::c_ulong, _: ...) -> libc::c_int;
    fn __ctype_b_loc() -> *mut *const libc::c_ushort;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;

    fn mkdtemp(__template: *mut libc::c_char) -> *mut libc::c_char;
    fn system(__command: *const libc::c_char) -> libc::c_int;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;

    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;

    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn xvasprintf(
        _: *mut *mut libc::c_char,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn sshpkt_get_end(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_get_cstring(
        ssh: *mut ssh,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshpkt_get_string_direct(
        ssh: *mut ssh,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshpkt_get_string(ssh: *mut ssh, valp: *mut *mut u_char, lenp: *mut size_t) -> libc::c_int;
    fn sshpkt_get_u32(ssh: *mut ssh, valp: *mut u_int32_t) -> libc::c_int;
    fn sshpkt_get_u8(ssh: *mut ssh, valp: *mut u_char) -> libc::c_int;
    fn sshpkt_put_stringb(ssh: *mut ssh, v: *const crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshpkt_put_cstring(ssh: *mut ssh, v: *const libc::c_void) -> libc::c_int;
    fn sshpkt_put_u32(ssh: *mut ssh, val: u_int32_t) -> libc::c_int;
    fn sshpkt_put_u8(ssh: *mut ssh, val: u_char) -> libc::c_int;
    fn sshpkt_fatal(ssh: *mut ssh, r: libc::c_int, fmt: *const libc::c_char, _: ...) -> !;
    fn sshpkt_send(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_start(ssh: *mut ssh, type_0: u_char) -> libc::c_int;
    fn ssh_packet_get_rekey_timeout(_: *mut ssh) -> time_t;
    fn ssh_packet_inc_alive_timeouts(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_set_alive_timeouts(_: *mut ssh, _: libc::c_int);
    fn ssh_tty_make_modes(_: *mut ssh, _: libc::c_int, _: *mut termios);
    fn ssh_packet_remaining(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_not_very_much_data_to_write(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_have_data_to_write(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_write_wait(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_write_poll(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_get_bytes(_: *mut ssh, _: *mut u_int64_t, _: *mut u_int64_t);
    fn ssh_packet_process_read(_: *mut ssh, _: libc::c_int) -> libc::c_int;
    fn ssh_packet_set_interactive(_: *mut ssh, _: libc::c_int, _: libc::c_int, _: libc::c_int);
    fn dispatch_protocol_error(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn ssh_dispatch_init(_: *mut ssh, _: Option<dispatch_fn>);
    fn ssh_dispatch_set(_: *mut ssh, _: libc::c_int, _: Option<dispatch_fn>);
    fn ssh_dispatch_run_fatal(_: *mut ssh, _: libc::c_int, _: *mut sig_atomic_t);
    fn ssh_packet_get_connection_in(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_get_connection_out(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_is_rekeying(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_check_rekey(_: *mut ssh) -> libc::c_int;

    fn sshbuf_free(buf: *mut crate::sshbuf::sshbuf);
    fn sshbuf_reset(buf: *mut crate::sshbuf::sshbuf);
    fn sshbuf_len(buf: *const crate::sshbuf::sshbuf) -> size_t;
    fn sshbuf_ptr(buf: *const crate::sshbuf::sshbuf) -> *const u_char;
    fn sshbuf_mutable_ptr(buf: *const crate::sshbuf::sshbuf) -> *mut u_char;
    fn sshbuf_consume(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_putf(
        buf: *mut crate::sshbuf::sshbuf,
        fmt: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut crate::sshbuf::sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_put_u8(buf: *mut crate::sshbuf::sshbuf, val: u_char) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut crate::sshbuf::sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
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
    fn channel_free_all(_: *mut ssh);
    fn channel_stop_listening(_: *mut ssh);
    fn channel_force_close(_: *mut ssh, _: *mut Channel, _: libc::c_int);
    fn channel_request_start(_: *mut ssh, _: libc::c_int, _: *mut libc::c_char, _: libc::c_int);
    fn channel_register_cleanup(
        _: *mut ssh,
        _: libc::c_int,
        _: Option<channel_callback_fn>,
        _: libc::c_int,
    );
    fn channel_register_open_confirm(
        _: *mut ssh,
        _: libc::c_int,
        _: Option<channel_open_fn>,
        _: *mut libc::c_void,
    );
    fn channel_register_filter(
        _: *mut ssh,
        _: libc::c_int,
        _: Option<channel_infilter_fn>,
        _: Option<channel_outfilter_fn>,
        _: Option<channel_filter_cleanup_fn>,
        _: *mut libc::c_void,
    );
    fn channel_register_status_confirm(
        _: *mut ssh,
        _: libc::c_int,
        _: Option<channel_confirm_cb>,
        _: Option<channel_confirm_abandon_cb>,
        _: *mut libc::c_void,
    );
    fn channel_cancel_cleanup(_: *mut ssh, _: libc::c_int);
    fn channel_send_window_changes(_: *mut ssh);
    fn channel_proxy_upstream(
        _: *mut Channel,
        _: libc::c_int,
        _: u_int32_t,
        _: *mut ssh,
    ) -> libc::c_int;
    fn channel_input_data(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_input_extended_data(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_input_ieof(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_input_oclose(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_input_open_confirmation(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_input_open_failure(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_input_window_adjust(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_input_status_confirm(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn channel_prepare_poll(
        _: *mut ssh,
        _: *mut *mut pollfd,
        _: *mut u_int,
        _: *mut u_int,
        _: u_int,
        _: *mut libc::timespec,
    );
    fn channel_after_poll(_: *mut ssh, _: *mut pollfd, _: u_int);
    fn channel_output_poll(_: *mut ssh);
    fn channel_still_open(_: *mut ssh) -> libc::c_int;
    fn channel_open_message(_: *mut ssh) -> *mut libc::c_char;
    fn channel_connect_by_listen_address(
        _: *mut ssh,
        _: *const libc::c_char,
        _: u_short,
        _: *mut libc::c_char,
        _: *mut libc::c_char,
    ) -> *mut Channel;
    fn channel_connect_by_listen_path(
        _: *mut ssh,
        _: *const libc::c_char,
        _: *mut libc::c_char,
        _: *mut libc::c_char,
    ) -> *mut Channel;
    fn channel_request_remote_forwarding(_: *mut ssh, _: *mut Forward) -> libc::c_int;
    fn channel_setup_local_fwd_listener(
        _: *mut ssh,
        _: *mut Forward,
        _: *mut ForwardOptions,
    ) -> libc::c_int;
    fn channel_request_rforward_cancel(_: *mut ssh, _: *mut Forward) -> libc::c_int;
    fn channel_cancel_lport_listener(
        _: *mut ssh,
        _: *mut Forward,
        _: libc::c_int,
        _: *mut ForwardOptions,
    ) -> libc::c_int;
    fn channel_set_x11_refuse_time(_: *mut ssh, _: time_t);
    fn x11_connect_display(_: *mut ssh) -> libc::c_int;
    fn chan_rcvd_eow(_: *mut ssh, _: *mut Channel);
    fn chan_read_failed(_: *mut ssh, _: *mut Channel);
    fn chan_write_failed(_: *mut ssh, _: *mut Channel);
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_equal(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_fingerprint(_: *const sshkey, _: libc::c_int, _: sshkey_fp_rep) -> *mut libc::c_char;
    fn sshkey_type(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_type_from_name(_: *const libc::c_char) -> libc::c_int;
    fn sshkey_is_cert(_: *const sshkey) -> libc::c_int;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
    fn sshkey_ssh_name(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_from_blob(_: *const u_char, _: size_t, _: *mut *mut sshkey) -> libc::c_int;
    fn sshkey_get_sigtype(_: *const u_char, _: size_t, _: *mut *mut libc::c_char) -> libc::c_int;
    fn sshkey_verify(
        _: *const sshkey,
        _: *const u_char,
        _: size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: u_int,
        _: *mut *mut sshkey_sig_details,
    ) -> libc::c_int;
    fn sshkey_puts(_: *const sshkey, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn sshkey_putb(_: *const sshkey, _: *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn kex_start_rekex(_: *mut ssh) -> libc::c_int;
    fn kex_input_kexinit(_: libc::c_int, _: u_int32_t, _: *mut ssh) -> libc::c_int;
    fn log_change_level(_: LogLevel) -> libc::c_int;
    fn log_is_on_stderr() -> libc::c_int;
    fn log_level_name(_: LogLevel) -> *const libc::c_char;

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
    fn monotime() -> time_t;
    fn monotime_double() -> libc::c_double;
    fn tun_open(_: libc::c_int, _: libc::c_int, _: *mut *mut libc::c_char) -> libc::c_int;
    fn mktemp_proto(_: *mut libc::c_char, _: size_t);
    fn ptimeout_init(pt: *mut libc::timespec);
    fn ptimeout_deadline_sec(pt: *mut libc::timespec, sec: libc::c_long);
    fn ptimeout_deadline_monotime(pt: *mut libc::timespec, when: time_t);
    fn ptimeout_get_ms(pt: *mut libc::timespec) -> libc::c_int;
    fn read_passphrase(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;

    fn parse_forward(
        _: *mut Forward,
        _: *const libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
    ) -> libc::c_int;
    fn option_clear_or_none(_: *const libc::c_char) -> libc::c_int;
    fn mux_exit_message(_: *mut ssh, _: *mut Channel, _: libc::c_int);
    fn mux_tty_alloc_failed(ssh: *mut ssh, _: *mut Channel);
    fn ssh_kill_proxy_command();
    fn get_hostfile_hostname_ipaddr(
        _: *mut libc::c_char,
        _: *mut sockaddr,
        _: u_short,
        _: *mut *mut libc::c_char,
        _: *mut *mut libc::c_char,
    );
    fn ssh_local_cmd(_: *const libc::c_char) -> libc::c_int;
    fn ssh_get_authentication_socket(fdp: *mut libc::c_int) -> libc::c_int;
    fn ssh_get_authentication_socket_path(
        authsocket: *const libc::c_char,
        fdp: *mut libc::c_int,
    ) -> libc::c_int;
    fn ssh_agent_bind_hostkey(
        sock: libc::c_int,
        key: *const sshkey,
        session_id: *const crate::sshbuf::sshbuf,
        signature: *const crate::sshbuf::sshbuf,
        forwarding: libc::c_int,
    ) -> libc::c_int;

    fn get_saved_tio() -> *mut termios;
    fn leave_raw_mode(_: libc::c_int);
    fn enter_raw_mode(_: libc::c_int);
    fn match_pattern(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn match_pattern_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn hostfile_replace_entries(
        filename: *const libc::c_char,
        host_0: *const libc::c_char,
        ip: *const libc::c_char,
        keys: *mut *mut sshkey,
        nkeys: size_t,
        store_hash: libc::c_int,
        quiet: libc::c_int,
        hash_alg: libc::c_int,
    ) -> libc::c_int;
    fn hostkeys_foreach(
        path: *const libc::c_char,
        callback: Option<hostkeys_foreach_fn>,
        ctx: *mut libc::c_void,
        host_0: *const libc::c_char,
        ip: *const libc::c_char,
        options_0: u_int,
        note: u_int,
    ) -> libc::c_int;
    static mut options: Options;
    static mut muxserver_sock: libc::c_int;
    static mut host: *mut libc::c_char;
    static mut forward_agent_sock_path: *mut libc::c_char;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type __u_char = libc::c_uchar;
pub type __u_short = libc::c_ushort;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
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
pub type u_short = __u_short;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type mode_t = __mode_t;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int8_t = __uint8_t;
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
pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;
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
pub type va_list = __builtin_va_list;
pub type nfds_t = libc::c_ulong;
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
    pub sk_key_handle: *mut crate::sshbuf::sshbuf,
    pub sk_reserved: *mut crate::sshbuf::sshbuf,
    pub cert: *mut sshkey_cert,
    pub shielded_private: *mut u_char,
    pub shielded_len: size_t,
    pub shield_prekey: *mut u_char,
    pub shield_prekey_len: size_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_cert {
    pub certblob: *mut crate::sshbuf::sshbuf,
    pub type_0: u_int,
    pub serial: u_int64_t,
    pub key_id: *mut libc::c_char,
    pub nprincipals: u_int,
    pub principals: *mut *mut libc::c_char,
    pub valid_after: u_int64_t,
    pub valid_before: u_int64_t,
    pub critical: *mut crate::sshbuf::sshbuf,
    pub extensions: *mut crate::sshbuf::sshbuf,
    pub signature_key: *mut sshkey,
    pub signature_type: *mut libc::c_char,
}
pub type EC_KEY = ec_key_st;
pub type DSA = dsa_st;
pub type RSA = rsa_st;
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
pub struct kex {
    pub newkeys: [*mut newkeys; 2],
    pub we_need: u_int,
    pub dh_need: u_int,
    pub server: libc::c_int,
    pub name: *mut libc::c_char,
    pub hostkey_alg: *mut libc::c_char,
    pub hostkey_type: libc::c_int,
    pub hostkey_nid: libc::c_int,
    pub kex_type: u_int,
    pub server_sig_algs: *mut libc::c_char,
    pub ext_info_c: libc::c_int,
    pub my: *mut crate::sshbuf::sshbuf,
    pub peer: *mut crate::sshbuf::sshbuf,
    pub client_version: *mut crate::sshbuf::sshbuf,
    pub server_version: *mut crate::sshbuf::sshbuf,
    pub session_id: *mut crate::sshbuf::sshbuf,
    pub initial_sig: *mut crate::sshbuf::sshbuf,
    pub initial_hostkey: *mut sshkey,
    pub done: sig_atomic_t,
    pub flags: u_int,
    pub hash_alg: libc::c_int,
    pub ec_nid: libc::c_int,
    pub failed_choice: *mut libc::c_char,
    pub verify_host_key: Option<unsafe extern "C" fn(*mut sshkey, *mut ssh) -> libc::c_int>,
    pub load_host_public_key:
        Option<unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut sshkey>,
    pub load_host_private_key:
        Option<unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut sshkey>,
    pub host_key_index:
        Option<unsafe extern "C" fn(*mut sshkey, libc::c_int, *mut ssh) -> libc::c_int>,
    pub sign: Option<
        unsafe extern "C" fn(
            *mut ssh,
            *mut sshkey,
            *mut sshkey,
            *mut *mut u_char,
            *mut size_t,
            *const u_char,
            size_t,
            *const libc::c_char,
        ) -> libc::c_int,
    >,
    pub kex: [Option<unsafe extern "C" fn(*mut ssh) -> libc::c_int>; 10],
    pub dh: *mut DH,
    pub min: u_int,
    pub max: u_int,
    pub nbits: u_int,
    pub ec_client_key: *mut EC_KEY,
    pub ec_group: *const EC_GROUP,
    pub c25519_client_key: [u_char; 32],
    pub c25519_client_pubkey: [u_char; 32],
    pub sntrup761_client_key: [u_char; 1763],
    pub client_pub: *mut crate::sshbuf::sshbuf,
}
pub type EC_GROUP = ec_group_st;
pub type DH = dh_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct newkeys {
    pub enc: sshenc,
    pub mac: sshmac,
    pub comp: sshcomp,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshcomp {
    pub type_0: u_int,
    pub enabled: libc::c_int,
    pub name: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshmac {
    pub name: *mut libc::c_char,
    pub enabled: libc::c_int,
    pub mac_len: u_int,
    pub key: *mut u_char,
    pub key_len: u_int,
    pub type_0: libc::c_int,
    pub etm: libc::c_int,
    pub hmac_ctx: *mut ssh_hmac_ctx,
    pub umac_ctx: *mut umac_ctx,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshenc {
    pub name: *mut libc::c_char,
    pub cipher: *const sshcipher,
    pub enabled: libc::c_int,
    pub key_len: u_int,
    pub iv_len: u_int,
    pub block_size: u_int,
    pub key: *mut u_char,
    pub iv: *mut u_char,
}
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
    pub entry: C2RustUnnamed_2,
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
pub struct C2RustUnnamed_2 {
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
pub type C2RustUnnamed_3 = libc::c_uint;
pub const _ISalnum: C2RustUnnamed_3 = 8;
pub const _ISpunct: C2RustUnnamed_3 = 4;
pub const _IScntrl: C2RustUnnamed_3 = 2;
pub const _ISblank: C2RustUnnamed_3 = 1;
pub const _ISgraph: C2RustUnnamed_3 = 32768;
pub const _ISprint: C2RustUnnamed_3 = 16384;
pub const _ISspace: C2RustUnnamed_3 = 8192;
pub const _ISxdigit: C2RustUnnamed_3 = 4096;
pub const _ISdigit: C2RustUnnamed_3 = 2048;
pub const _ISalpha: C2RustUnnamed_3 = 1024;
pub const _ISlower: C2RustUnnamed_3 = 512;
pub const _ISupper: C2RustUnnamed_3 = 256;
pub type C2RustUnnamed_4 = libc::c_uint;
pub const DISPATCH_NONBLOCK: C2RustUnnamed_4 = 1;
pub const DISPATCH_BLOCK: C2RustUnnamed_4 = 0;
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
pub type sshkey_types = libc::c_uint;
pub const KEY_UNSPEC: sshkey_types = 14;
pub const KEY_ED25519_SK_CERT: sshkey_types = 13;
pub const KEY_ED25519_SK: sshkey_types = 12;
pub const KEY_ECDSA_SK_CERT: sshkey_types = 11;
pub const KEY_ECDSA_SK: sshkey_types = 10;
pub const KEY_XMSS_CERT: sshkey_types = 9;
pub const KEY_XMSS: sshkey_types = 8;
pub const KEY_ED25519_CERT: sshkey_types = 7;
pub const KEY_ECDSA_CERT: sshkey_types = 6;
pub const KEY_DSA_CERT: sshkey_types = 5;
pub const KEY_RSA_CERT: sshkey_types = 4;
pub const KEY_ED25519: sshkey_types = 3;
pub const KEY_ECDSA: sshkey_types = 2;
pub const KEY_DSA: sshkey_types = 1;
pub const KEY_RSA: sshkey_types = 0;
pub type sshkey_fp_rep = libc::c_uint;
pub const SSH_FP_RANDOMART: sshkey_fp_rep = 4;
pub const SSH_FP_BUBBLEBABBLE: sshkey_fp_rep = 3;
pub const SSH_FP_BASE64: sshkey_fp_rep = 2;
pub const SSH_FP_HEX: sshkey_fp_rep = 1;
pub const SSH_FP_DEFAULT: sshkey_fp_rep = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshkey_sig_details {
    pub sk_counter: uint32_t,
    pub sk_flags: uint8_t,
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
pub struct Options {
    pub host_arg: *mut libc::c_char,
    pub forward_agent: libc::c_int,
    pub forward_agent_sock_path: *mut libc::c_char,
    pub forward_x11: libc::c_int,
    pub forward_x11_timeout: libc::c_int,
    pub forward_x11_trusted: libc::c_int,
    pub exit_on_forward_failure: libc::c_int,
    pub xauth_location: *mut libc::c_char,
    pub fwd_opts: ForwardOptions,
    pub pubkey_authentication: libc::c_int,
    pub hostbased_authentication: libc::c_int,
    pub gss_authentication: libc::c_int,
    pub gss_deleg_creds: libc::c_int,
    pub password_authentication: libc::c_int,
    pub kbd_interactive_authentication: libc::c_int,
    pub kbd_interactive_devices: *mut libc::c_char,
    pub batch_mode: libc::c_int,
    pub check_host_ip: libc::c_int,
    pub strict_host_key_checking: libc::c_int,
    pub compression: libc::c_int,
    pub tcp_keep_alive: libc::c_int,
    pub ip_qos_interactive: libc::c_int,
    pub ip_qos_bulk: libc::c_int,
    pub log_facility: SyslogFacility,
    pub log_level: LogLevel,
    pub num_log_verbose: u_int,
    pub log_verbose: *mut *mut libc::c_char,
    pub port: libc::c_int,
    pub address_family: libc::c_int,
    pub connection_attempts: libc::c_int,
    pub connection_timeout: libc::c_int,
    pub number_of_password_prompts: libc::c_int,
    pub ciphers: *mut libc::c_char,
    pub macs: *mut libc::c_char,
    pub hostkeyalgorithms: *mut libc::c_char,
    pub kex_algorithms: *mut libc::c_char,
    pub ca_sign_algorithms: *mut libc::c_char,
    pub hostname: *mut libc::c_char,
    pub host_key_alias: *mut libc::c_char,
    pub proxy_command: *mut libc::c_char,
    pub user: *mut libc::c_char,
    pub escape_char: libc::c_int,
    pub num_system_hostfiles: u_int,
    pub system_hostfiles: [*mut libc::c_char; 32],
    pub num_user_hostfiles: u_int,
    pub user_hostfiles: [*mut libc::c_char; 32],
    pub preferred_authentications: *mut libc::c_char,
    pub bind_address: *mut libc::c_char,
    pub bind_interface: *mut libc::c_char,
    pub pkcs11_provider: *mut libc::c_char,
    pub sk_provider: *mut libc::c_char,
    pub verify_host_key_dns: libc::c_int,
    pub num_identity_files: libc::c_int,
    pub identity_files: [*mut libc::c_char; 100],
    pub identity_file_userprovided: [libc::c_int; 100],
    pub identity_keys: [*mut sshkey; 100],
    pub num_certificate_files: libc::c_int,
    pub certificate_files: [*mut libc::c_char; 100],
    pub certificate_file_userprovided: [libc::c_int; 100],
    pub certificates: [*mut sshkey; 100],
    pub add_keys_to_agent: libc::c_int,
    pub add_keys_to_agent_lifespan: libc::c_int,
    pub identity_agent: *mut libc::c_char,
    pub num_local_forwards: libc::c_int,
    pub local_forwards: *mut Forward,
    pub num_remote_forwards: libc::c_int,
    pub remote_forwards: *mut Forward,
    pub clear_forwardings: libc::c_int,
    pub permitted_remote_opens: *mut *mut libc::c_char,
    pub num_permitted_remote_opens: u_int,
    pub stdio_forward_host: *mut libc::c_char,
    pub stdio_forward_port: libc::c_int,
    pub enable_ssh_keysign: libc::c_int,
    pub rekey_limit: int64_t,
    pub rekey_interval: libc::c_int,
    pub no_host_authentication_for_localhost: libc::c_int,
    pub identities_only: libc::c_int,
    pub server_alive_interval: libc::c_int,
    pub server_alive_count_max: libc::c_int,
    pub num_send_env: u_int,
    pub send_env: *mut *mut libc::c_char,
    pub num_setenv: u_int,
    pub setenv: *mut *mut libc::c_char,
    pub control_path: *mut libc::c_char,
    pub control_master: libc::c_int,
    pub control_persist: libc::c_int,
    pub control_persist_timeout: libc::c_int,
    pub hash_known_hosts: libc::c_int,
    pub tun_open: libc::c_int,
    pub tun_local: libc::c_int,
    pub tun_remote: libc::c_int,
    pub local_command: *mut libc::c_char,
    pub permit_local_command: libc::c_int,
    pub remote_command: *mut libc::c_char,
    pub visual_host_key: libc::c_int,
    pub request_tty: libc::c_int,
    pub session_type: libc::c_int,
    pub stdin_null: libc::c_int,
    pub fork_after_authentication: libc::c_int,
    pub proxy_use_fdpass: libc::c_int,
    pub num_canonical_domains: libc::c_int,
    pub canonical_domains: [*mut libc::c_char; 32],
    pub canonicalize_hostname: libc::c_int,
    pub canonicalize_max_dots: libc::c_int,
    pub canonicalize_fallback_local: libc::c_int,
    pub num_permitted_cnames: libc::c_int,
    pub permitted_cnames: [allowed_cname; 32],
    pub revoked_host_keys: *mut libc::c_char,
    pub fingerprint_hash: libc::c_int,
    pub update_hostkeys: libc::c_int,
    pub hostbased_accepted_algos: *mut libc::c_char,
    pub pubkey_accepted_algos: *mut libc::c_char,
    pub jump_user: *mut libc::c_char,
    pub jump_host: *mut libc::c_char,
    pub jump_port: libc::c_int,
    pub jump_extra: *mut libc::c_char,
    pub known_hosts_command: *mut libc::c_char,
    pub required_rsa_size: libc::c_int,
    pub enable_escape_commandline: libc::c_int,
    pub ignored_unknown: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct allowed_cname {
    pub source_list: *mut libc::c_char,
    pub target_list: *mut libc::c_char,
}
pub type sshsig_t = Option<unsafe extern "C" fn(libc::c_int) -> ()>;
pub type global_confirm_cb =
    unsafe extern "C" fn(*mut ssh, libc::c_int, u_int32_t, *mut libc::c_void) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct global_confirm {
    pub entry: C2RustUnnamed_5,
    pub cb: Option<global_confirm_cb>,
    pub ctx: *mut libc::c_void,
    pub ref_count: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_5 {
    pub tqe_next: *mut global_confirm,
    pub tqe_prev: *mut *mut global_confirm,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct global_confirms {
    pub tqh_first: *mut global_confirm,
    pub tqh_last: *mut *mut global_confirm,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct escape_filter_ctx {
    pub escape_pending: libc::c_int,
    pub escape_char: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct escape_help_text {
    pub cmd: *const libc::c_char,
    pub text: *const libc::c_char,
    pub flags: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostkeys_update_ctx {
    pub host_str: *mut libc::c_char,
    pub ip_str: *mut libc::c_char,
    pub keys: *mut *mut sshkey,
    pub keys_match: *mut u_int,
    pub keys_verified: *mut libc::c_int,
    pub nkeys: size_t,
    pub nnew: size_t,
    pub nincomplete: size_t,
    pub old_keys: *mut *mut sshkey,
    pub nold: size_t,
    pub complex_hostspec: libc::c_int,
    pub ca_available: libc::c_int,
    pub old_key_seen: libc::c_int,
    pub other_name_seen: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostkey_foreach_line {
    pub path: *const libc::c_char,
    pub linenum: u_long,
    pub status: u_int,
    pub match_0: u_int,
    pub line: *mut libc::c_char,
    pub marker: libc::c_int,
    pub hosts: *const libc::c_char,
    pub rawkey: *const libc::c_char,
    pub keytype: libc::c_int,
    pub key: *mut sshkey,
    pub comment: *const libc::c_char,
    pub note: u_int,
}
pub type hostkeys_foreach_fn =
    unsafe extern "C" fn(*mut hostkey_foreach_line, *mut libc::c_void) -> libc::c_int;
pub const MRK_NONE: C2RustUnnamed_6 = 1;
pub type confirm_action = libc::c_uint;
pub const CONFIRM_TTY: confirm_action = 2;
pub const CONFIRM_CLOSE: confirm_action = 1;
pub const CONFIRM_WARN: confirm_action = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct channel_reply_ctx {
    pub request_type: *const libc::c_char,
    pub id: libc::c_int,
    pub action: confirm_action,
}
pub type C2RustUnnamed_6 = libc::c_uint;
pub const MRK_CA: C2RustUnnamed_6 = 3;
pub const MRK_REVOKE: C2RustUnnamed_6 = 2;
pub const MRK_ERROR: C2RustUnnamed_6 = 0;
static mut received_window_change_signal: sig_atomic_t = 0 as libc::c_int;
static mut received_signal: sig_atomic_t = 0 as libc::c_int;
static mut control_persist_exit_time: time_t = 0 as libc::c_int as time_t;
pub static mut quit_pending: sig_atomic_t = 0;
static mut last_was_cr: libc::c_int = 0;
static mut exit_status: libc::c_int = 0;
static mut stderr_buffer: *mut crate::sshbuf::sshbuf =
    0 as *const crate::sshbuf::sshbuf as *mut crate::sshbuf::sshbuf;
static mut connection_in: libc::c_int = 0;
static mut connection_out: libc::c_int = 0;
static mut need_rekeying: libc::c_int = 0;
static mut session_closed: libc::c_int = 0;
static mut x11_refuse_time: time_t = 0;
static mut server_alive_time: time_t = 0;
static mut hostkeys_update_complete: libc::c_int = 0;
static mut session_setup_complete: libc::c_int = 0;
pub static mut session_ident: libc::c_int = -(1 as libc::c_int);
static mut global_confirms: global_confirms = global_confirms {
    tqh_first: 0 as *const global_confirm as *mut global_confirm,
    tqh_last: 0 as *const *mut global_confirm as *mut *mut global_confirm,
};
unsafe extern "C" fn quit_message(mut fmt: *const libc::c_char, mut args: ...) {
    let mut msg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut args_0: ::core::ffi::VaListImpl;
    let mut r: libc::c_int = 0;
    args_0 = args.clone();
    xvasprintf(&mut msg, fmt, args_0.as_va_list());
    r = sshbuf_putf(
        stderr_buffer,
        b"%s\r\n\0" as *const u8 as *const libc::c_char,
        msg,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"quit_message\0")).as_ptr(),
            210 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
        );
    }
    ::core::ptr::write_volatile(&mut quit_pending as *mut sig_atomic_t, 1 as libc::c_int);
}
unsafe extern "C" fn window_change_handler(mut _sig: libc::c_int) {
    ::core::ptr::write_volatile(
        &mut received_window_change_signal as *mut sig_atomic_t,
        1 as libc::c_int,
    );
}
unsafe extern "C" fn signal_handler(mut sig: libc::c_int) {
    ::core::ptr::write_volatile(&mut received_signal as *mut sig_atomic_t, sig);
    ::core::ptr::write_volatile(&mut quit_pending as *mut sig_atomic_t, 1 as libc::c_int);
}
unsafe extern "C" fn set_control_persist_exit_time(mut ssh: *mut ssh) {
    if muxserver_sock == -(1 as libc::c_int)
        || options.control_persist == 0
        || options.control_persist_timeout == 0 as libc::c_int
    {
        control_persist_exit_time = 0 as libc::c_int as time_t;
    } else if channel_still_open(ssh) != 0 {
        if control_persist_exit_time > 0 as libc::c_int as libc::c_long {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                    b"set_control_persist_exit_time\0",
                ))
                .as_ptr(),
                251 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"cancel scheduled libc::exit\0" as *const u8 as *const libc::c_char,
            );
        }
        control_persist_exit_time = 0 as libc::c_int as time_t;
    } else if control_persist_exit_time <= 0 as libc::c_int as libc::c_long {
        control_persist_exit_time = monotime() + options.control_persist_timeout as time_t;
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"set_control_persist_exit_time\0",
            ))
            .as_ptr(),
            258 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"schedule libc::exit in %d seconds\0" as *const u8 as *const libc::c_char,
            options.control_persist_timeout,
        );
    }
}
unsafe extern "C" fn client_x11_display_valid(mut display: *const libc::c_char) -> libc::c_int {
    let mut i: size_t = 0;
    let mut dlen: size_t = 0;
    if display.is_null() {
        return 0 as libc::c_int;
    }
    dlen = strlen(display);
    i = 0 as libc::c_int as size_t;
    while i < dlen {
        if *(*__ctype_b_loc()).offset(*display.offset(i as isize) as u_char as libc::c_int as isize)
            as libc::c_int
            & _ISalnum as libc::c_int as libc::c_ushort as libc::c_int
            == 0
            && (libc::strchr(
                b":/.-_\0" as *const u8 as *const libc::c_char,
                *display.offset(i as isize) as libc::c_int,
            ))
            .is_null()
        {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"client_x11_display_valid\0",
                ))
                .as_ptr(),
                276 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Invalid character '%c' in DISPLAY\0" as *const u8 as *const libc::c_char,
                *display.offset(i as isize) as libc::c_int,
            );
            return 0 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn client_x11_get_proto(
    mut ssh: *mut ssh,
    mut display: *const libc::c_char,
    mut xauth_path: *const libc::c_char,
    mut trusted: u_int,
    mut timeout: u_int,
    mut _proto: *mut *mut libc::c_char,
    mut _data: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut cmd: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut line: [libc::c_char; 512] = [0; 512];
    let mut xdisplay: [libc::c_char; 512] = [0; 512];
    let mut xauthfile: [libc::c_char; 4096] = [0; 4096];
    let mut xauthdir: [libc::c_char; 4096] = [0; 4096];
    static mut proto: [libc::c_char; 512] = [0; 512];
    static mut data: [libc::c_char; 512] = [0; 512];
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut got_data: libc::c_int = 0 as libc::c_int;
    let mut generated: libc::c_int = 0 as libc::c_int;
    let mut do_unlink: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    let mut now: u_int = 0;
    let mut x11_timeout_real: u_int = 0;
    *_proto = proto.as_mut_ptr();
    *_data = data.as_mut_ptr();
    xauthdir[0 as libc::c_int as usize] = '\0' as i32 as libc::c_char;
    xauthfile[0 as libc::c_int as usize] = xauthdir[0 as libc::c_int as usize];
    data[0 as libc::c_int as usize] = xauthfile[0 as libc::c_int as usize];
    proto[0 as libc::c_int as usize] = data[0 as libc::c_int as usize];
    if client_x11_display_valid(display) == 0 {
        if !display.is_null() {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"client_x11_get_proto\0",
                ))
                .as_ptr(),
                305 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"DISPLAY \"%s\" invalid; disabling X11 forwarding\0" as *const u8
                    as *const libc::c_char,
                display,
            );
        }
        return -(1 as libc::c_int);
    }
    if !xauth_path.is_null() && libc::stat(xauth_path, &mut st) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"client_x11_get_proto\0"))
                .as_ptr(),
            309 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"No xauth program.\0" as *const u8 as *const libc::c_char,
        );
        xauth_path = 0 as *const libc::c_char;
    }
    if !xauth_path.is_null() {
        if strncmp(
            display,
            b"localhost:\0" as *const u8 as *const libc::c_char,
            10 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            r = libc::snprintf(
                xdisplay.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 512]>() as usize,
                b"unix:%s\0" as *const u8 as *const libc::c_char,
                display.offset(10 as libc::c_int as isize),
            );
            if r < 0 as libc::c_int
                || r as size_t >= ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong
            {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"client_x11_get_proto\0",
                    ))
                    .as_ptr(),
                    325 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"display name too long\0" as *const u8 as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
            display = xdisplay.as_mut_ptr();
        }
        if trusted == 0 as libc::c_int as libc::c_uint {
            mktemp_proto(
                xauthdir.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong,
            );
            if (mkdtemp(xauthdir.as_mut_ptr())).is_null() {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"client_x11_get_proto\0",
                    ))
                    .as_ptr(),
                    340 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"mkdtemp: %s\0" as *const u8 as *const libc::c_char,
                    libc::strerror(*libc::__errno_location()),
                );
                return -(1 as libc::c_int);
            }
            do_unlink = 1 as libc::c_int;
            r = libc::snprintf(
                xauthfile.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 4096]>() as usize,
                b"%s/xauthfile\0" as *const u8 as *const libc::c_char,
                xauthdir.as_mut_ptr(),
            );
            if r < 0 as libc::c_int
                || r as size_t >= ::core::mem::size_of::<[libc::c_char; 4096]>() as libc::c_ulong
            {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                        b"client_x11_get_proto\0",
                    ))
                    .as_ptr(),
                    347 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"xauthfile path too long\0" as *const u8 as *const libc::c_char,
                );
                rmdir(xauthdir.as_mut_ptr());
                return -(1 as libc::c_int);
            }
            if timeout == 0 as libc::c_int as libc::c_uint {
                crate::xmalloc::xasprintf(
                    &mut cmd as *mut *mut libc::c_char,
                    b"%s -f %s generate %s %s untrusted 2>%s\0" as *const u8 as *const libc::c_char,
                    xauth_path,
                    xauthfile.as_mut_ptr(),
                    display,
                    b"MIT-MAGIC-COOKIE-1\0" as *const u8 as *const libc::c_char,
                    b"/dev/null\0" as *const u8 as *const libc::c_char,
                );
            } else {
                if timeout
                    < (2147483647 as libc::c_int as libc::c_uint)
                        .wrapping_mul(2 as libc::c_uint)
                        .wrapping_add(1 as libc::c_uint)
                        .wrapping_sub(60 as libc::c_int as libc::c_uint)
                {
                    x11_timeout_real = timeout.wrapping_add(60 as libc::c_int as libc::c_uint);
                } else {
                    x11_timeout_real = (2147483647 as libc::c_int as libc::c_uint)
                        .wrapping_mul(2 as libc::c_uint)
                        .wrapping_add(1 as libc::c_uint);
                }
                crate::xmalloc::xasprintf(
                    &mut cmd as *mut *mut libc::c_char,
                    b"%s -f %s generate %s %s untrusted timeout %u 2>%s\0" as *const u8
                        as *const libc::c_char,
                    xauth_path,
                    xauthfile.as_mut_ptr(),
                    display,
                    b"MIT-MAGIC-COOKIE-1\0" as *const u8 as *const libc::c_char,
                    x11_timeout_real,
                    b"/dev/null\0" as *const u8 as *const libc::c_char,
                );
            }
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"client_x11_get_proto\0",
                ))
                .as_ptr(),
                373 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"xauth command: %s\0" as *const u8 as *const libc::c_char,
                cmd,
            );
            if timeout != 0 as libc::c_int as libc::c_uint
                && x11_refuse_time == 0 as libc::c_int as libc::c_long
            {
                now = (monotime() + 1 as libc::c_int as libc::c_long) as u_int;
                if (9223372036854775807 as libc::c_longlong - timeout as libc::c_longlong)
                    < now as libc::c_longlong
                {
                    x11_refuse_time = 9223372036854775807 as libc::c_longlong as time_t;
                } else {
                    x11_refuse_time = now.wrapping_add(timeout) as time_t;
                }
                channel_set_x11_refuse_time(ssh, x11_refuse_time);
            }
            if system(cmd) == 0 as libc::c_int {
                generated = 1 as libc::c_int;
            }
            libc::free(cmd as *mut libc::c_void);
        }
        if trusted != 0 || generated != 0 {
            crate::xmalloc::xasprintf(
                &mut cmd as *mut *mut libc::c_char,
                b"%s %s%s list %s 2>/dev/null\0" as *const u8 as *const libc::c_char,
                xauth_path,
                if generated != 0 {
                    b"-f \0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                if generated != 0 {
                    xauthfile.as_mut_ptr() as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                display,
            );
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"client_x11_get_proto\0",
                ))
                .as_ptr(),
                401 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"x11_get_proto: %s\0" as *const u8 as *const libc::c_char,
                cmd,
            );
            f = popen(cmd, b"r\0" as *const u8 as *const libc::c_char);
            if !f.is_null()
                && !(fgets(
                    line.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong as libc::c_int,
                    f,
                ))
                .is_null()
                && sscanf(
                    line.as_mut_ptr(),
                    b"%*s %511s %511s\0" as *const u8 as *const libc::c_char,
                    proto.as_mut_ptr(),
                    data.as_mut_ptr(),
                ) == 2 as libc::c_int
            {
                got_data = 1 as libc::c_int;
            }
            if !f.is_null() {
                pclose(f);
            }
            libc::free(cmd as *mut libc::c_void);
        }
    }
    if do_unlink != 0 {
        unlink(xauthfile.as_mut_ptr());
        rmdir(xauthdir.as_mut_ptr());
    }
    if trusted == 0 && got_data == 0 {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"client_x11_get_proto\0"))
                .as_ptr(),
            420 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Warning: untrusted X11 forwarding setup failed: xauth key data not generated\0"
                as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if got_data == 0 {
        let mut rnd: [u_int8_t; 16] = [0; 16];
        let mut i: u_int = 0;
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"client_x11_get_proto\0"))
                .as_ptr(),
            437 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Warning: No xauth data; using fake authentication data for X11 forwarding.\0"
                as *const u8 as *const libc::c_char,
        );
        strlcpy(
            proto.as_mut_ptr(),
            b"MIT-MAGIC-COOKIE-1\0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
        );
        arc4random_buf(
            rnd.as_mut_ptr() as *mut libc::c_void,
            ::core::mem::size_of::<[u_int8_t; 16]>() as libc::c_ulong,
        );
        i = 0 as libc::c_int as u_int;
        while (i as libc::c_ulong) < ::core::mem::size_of::<[u_int8_t; 16]>() as libc::c_ulong {
            libc::snprintf(
                data.as_mut_ptr()
                    .offset((2 as libc::c_int as libc::c_uint).wrapping_mul(i) as isize),
                (::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong).wrapping_sub(
                    (2 as libc::c_int as libc::c_uint).wrapping_mul(i) as libc::c_ulong,
                ) as usize,
                b"%02x\0" as *const u8 as *const libc::c_char,
                rnd[i as usize] as libc::c_int,
            );
            i = i.wrapping_add(1);
            i;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn client_check_window_change(mut ssh: *mut ssh) {
    if received_window_change_signal == 0 {
        return;
    }
    ::core::ptr::write_volatile(
        &mut received_window_change_signal as *mut sig_atomic_t,
        0 as libc::c_int,
    );
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
            b"client_check_window_change\0",
        ))
        .as_ptr(),
        462 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"changed\0" as *const u8 as *const libc::c_char,
    );
    channel_send_window_changes(ssh);
}
unsafe extern "C" fn client_global_request_reply(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut gc: *mut global_confirm = 0 as *mut global_confirm;
    gc = global_confirms.tqh_first;
    if gc.is_null() {
        return 0 as libc::c_int;
    }
    if ((*gc).cb).is_some() {
        ((*gc).cb).expect("non-null function pointer")(ssh, type_0, seq, (*gc).ctx);
    }
    (*gc).ref_count -= 1;
    if (*gc).ref_count <= 0 as libc::c_int {
        if !((*gc).entry.tqe_next).is_null() {
            (*(*gc).entry.tqe_next).entry.tqe_prev = (*gc).entry.tqe_prev;
        } else {
            global_confirms.tqh_last = (*gc).entry.tqe_prev;
        }
        *(*gc).entry.tqe_prev = (*gc).entry.tqe_next;
        freezero(
            gc as *mut libc::c_void,
            ::core::mem::size_of::<global_confirm>() as libc::c_ulong,
        );
    }
    ssh_packet_set_alive_timeouts(ssh, 0 as libc::c_int);
    return 0 as libc::c_int;
}
unsafe extern "C" fn schedule_server_alive_check() {
    if options.server_alive_interval > 0 as libc::c_int {
        server_alive_time = monotime() + options.server_alive_interval as libc::c_long;
    }
}
unsafe extern "C" fn server_alive_check(mut ssh: *mut ssh) {
    let mut r: libc::c_int = 0;
    if ssh_packet_inc_alive_timeouts(ssh) > options.server_alive_count_max {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"server_alive_check\0"))
                .as_ptr(),
            497 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Timeout, server %s not responding.\0" as *const u8 as *const libc::c_char,
            host,
        );
        cleanup_exit(255 as libc::c_int);
    }
    r = sshpkt_start(ssh, 80 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_cstring(
                ssh,
                b"keepalive@openssh.com\0" as *const u8 as *const libc::c_char
                    as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u8(ssh, 1 as libc::c_int as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"server_alive_check\0"))
                .as_ptr(),
            504 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send packet\0" as *const u8 as *const libc::c_char,
        );
    }
    client_register_global_confirm(None, 0 as *mut libc::c_void);
    schedule_server_alive_check();
}
unsafe extern "C" fn client_wait_until_can_do_something(
    mut ssh: *mut ssh,
    mut pfdp: *mut *mut pollfd,
    mut npfd_allocp: *mut u_int,
    mut npfd_activep: *mut u_int,
    mut rekeying: libc::c_int,
    mut conn_in_readyp: *mut libc::c_int,
    mut conn_out_readyp: *mut libc::c_int,
) {
    let mut timeout: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut ret: libc::c_int = 0;
    let mut p: u_int = 0;
    *conn_out_readyp = 0 as libc::c_int;
    *conn_in_readyp = *conn_out_readyp;
    ptimeout_init(&mut timeout);
    channel_prepare_poll(
        ssh,
        pfdp,
        npfd_allocp,
        npfd_activep,
        2 as libc::c_int as u_int,
        &mut timeout,
    );
    if *npfd_activep < 2 as libc::c_int as libc::c_uint {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 35], &[libc::c_char; 35]>(
                b"client_wait_until_can_do_something\0",
            ))
            .as_ptr(),
            529 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"bad npfd %u\0" as *const u8 as *const libc::c_char,
            *npfd_activep,
        );
    }
    if session_closed != 0
        && channel_still_open(ssh) == 0
        && ssh_packet_have_data_to_write(ssh) == 0
    {
        p = 0 as libc::c_int as u_int;
        while p < *npfd_activep {
            (*(*pfdp).offset(p as isize)).revents = 0 as libc::c_int as libc::c_short;
            p = p.wrapping_add(1);
            p;
        }
        return;
    }
    (*(*pfdp).offset(0 as libc::c_int as isize)).fd = connection_in;
    (*(*pfdp).offset(0 as libc::c_int as isize)).events = 0x1 as libc::c_int as libc::c_short;
    (*(*pfdp).offset(1 as libc::c_int as isize)).fd = connection_out;
    (*(*pfdp).offset(1 as libc::c_int as isize)).events =
        (if ssh_packet_have_data_to_write(ssh) != 0 {
            0x4 as libc::c_int
        } else {
            0 as libc::c_int
        }) as libc::c_short;
    set_control_persist_exit_time(ssh);
    if control_persist_exit_time > 0 as libc::c_int as libc::c_long {
        ptimeout_deadline_monotime(&mut timeout, control_persist_exit_time);
    }
    if options.server_alive_interval > 0 as libc::c_int {
        ptimeout_deadline_monotime(&mut timeout, server_alive_time);
    }
    if options.rekey_interval > 0 as libc::c_int && rekeying == 0 {
        ptimeout_deadline_sec(&mut timeout, ssh_packet_get_rekey_timeout(ssh));
    }
    ret = poll(
        *pfdp,
        *npfd_activep as nfds_t,
        ptimeout_get_ms(&mut timeout),
    );
    if ret == -(1 as libc::c_int) {
        p = 0 as libc::c_int as u_int;
        while p < *npfd_activep {
            (*(*pfdp).offset(p as isize)).revents = 0 as libc::c_int as libc::c_short;
            p = p.wrapping_add(1);
            p;
        }
        if *libc::__errno_location() == 4 as libc::c_int {
            return;
        }
        quit_message(
            b"poll: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        return;
    }
    *conn_in_readyp = ((*(*pfdp).offset(0 as libc::c_int as isize)).revents as libc::c_int
        != 0 as libc::c_int) as libc::c_int;
    *conn_out_readyp = ((*(*pfdp).offset(1 as libc::c_int as isize)).revents as libc::c_int
        != 0 as libc::c_int) as libc::c_int;
    if options.server_alive_interval > 0 as libc::c_int
        && *conn_in_readyp == 0
        && monotime() >= server_alive_time
    {
        server_alive_check(ssh);
    }
}
unsafe extern "C" fn client_suspend_self(
    mut bin: *mut crate::sshbuf::sshbuf,
    mut bout: *mut crate::sshbuf::sshbuf,
    mut berr: *mut crate::sshbuf::sshbuf,
) {
    if sshbuf_len(bout) > 0 as libc::c_int as libc::c_ulong {
        atomicio(
            ::core::mem::transmute::<
                Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
                Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
            >(Some(
                write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
            )),
            fileno(stdout),
            sshbuf_mutable_ptr(bout) as *mut libc::c_void,
            sshbuf_len(bout),
        );
    }
    if sshbuf_len(berr) > 0 as libc::c_int as libc::c_ulong {
        atomicio(
            ::core::mem::transmute::<
                Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
                Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
            >(Some(
                write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
            )),
            fileno(stderr),
            sshbuf_mutable_ptr(berr) as *mut libc::c_void,
            sshbuf_len(berr),
        );
    }
    leave_raw_mode((options.request_tty == 3 as libc::c_int) as libc::c_int);
    sshbuf_reset(bin);
    sshbuf_reset(bout);
    sshbuf_reset(berr);
    kill(libc::getpid(), 20 as libc::c_int);
    ::core::ptr::write_volatile(
        &mut received_window_change_signal as *mut sig_atomic_t,
        1 as libc::c_int,
    );
    enter_raw_mode((options.request_tty == 3 as libc::c_int) as libc::c_int);
}
unsafe extern "C" fn client_process_net_input(mut ssh: *mut ssh) {
    let mut r: libc::c_int = 0;
    schedule_server_alive_check();
    r = ssh_packet_process_read(ssh, connection_in);
    if r == 0 as libc::c_int {
        return;
    }
    if r == -(24 as libc::c_int) {
        if *libc::__errno_location() == 11 as libc::c_int
            || *libc::__errno_location() == 4 as libc::c_int
            || *libc::__errno_location() == 11 as libc::c_int
        {
            return;
        }
        if *libc::__errno_location() == 32 as libc::c_int {
            quit_message(
                b"Connection to %s closed by remote host.\0" as *const u8 as *const libc::c_char,
                host,
            );
            return;
        }
    }
    quit_message(
        b"Read from remote host %s: %s\0" as *const u8 as *const libc::c_char,
        host,
        ssh_err(r),
    );
}
unsafe extern "C" fn client_status_confirm(
    mut ssh: *mut ssh,
    mut type_0: libc::c_int,
    mut c: *mut Channel,
    mut ctx: *mut libc::c_void,
) {
    let mut cr: *mut channel_reply_ctx = ctx as *mut channel_reply_ctx;
    let mut errmsg: [libc::c_char; 256] = [0; 256];
    let mut r: libc::c_int = 0;
    let mut tochan: libc::c_int = 0;
    if (*cr).action as libc::c_uint == CONFIRM_TTY as libc::c_int as libc::c_uint
        && (options.request_tty == 3 as libc::c_int || options.request_tty == 2 as libc::c_int)
    {
        (*cr).action = CONFIRM_CLOSE;
    }
    tochan = (options.log_level as libc::c_int >= SYSLOG_LEVEL_ERROR as libc::c_int
        && (*c).ctl_chan != -(1 as libc::c_int)
        && (*c).extended_usage == 2 as libc::c_int) as libc::c_int;
    if type_0 == 99 as libc::c_int {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"client_status_confirm\0"))
                .as_ptr(),
            664 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"%s request accepted on channel %d\0" as *const u8 as *const libc::c_char,
            (*cr).request_type,
            (*c).self_0,
        );
    } else if type_0 == 100 as libc::c_int {
        if tochan != 0 {
            libc::snprintf(
                errmsg.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
                b"%s request failed\r\n\0" as *const u8 as *const libc::c_char,
                (*cr).request_type,
            );
        } else {
            libc::snprintf(
                errmsg.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 256]>() as usize,
                b"%s request failed on channel %d\0" as *const u8 as *const libc::c_char,
                (*cr).request_type,
                (*c).self_0,
            );
        }
        if (*cr).action as libc::c_uint == CONFIRM_CLOSE as libc::c_int as libc::c_uint
            && (*c).self_0 == session_ident
        {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"client_status_confirm\0",
                ))
                .as_ptr(),
                676 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s\0" as *const u8 as *const libc::c_char,
                errmsg.as_mut_ptr(),
            );
        }
        if tochan != 0 {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"client_status_confirm\0",
                ))
                .as_ptr(),
                683 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"channel %d: mux request: %s\0" as *const u8 as *const libc::c_char,
                (*c).self_0,
                (*cr).request_type,
            );
            r = sshbuf_put(
                (*c).extended,
                errmsg.as_mut_ptr() as *const libc::c_void,
                strlen(errmsg.as_mut_ptr()),
            );
            if r != 0 as libc::c_int {
                sshfatal(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"client_status_confirm\0",
                    ))
                    .as_ptr(),
                    686 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"sshbuf_put\0" as *const u8 as *const libc::c_char,
                );
            }
        } else {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"client_status_confirm\0",
                ))
                .as_ptr(),
                688 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"%s\0" as *const u8 as *const libc::c_char,
                errmsg.as_mut_ptr(),
            );
        }
        if (*cr).action as libc::c_uint == CONFIRM_TTY as libc::c_int as libc::c_uint {
            if (*c).self_0 == session_ident {
                leave_raw_mode(0 as libc::c_int);
            } else {
                mux_tty_alloc_failed(ssh, c);
            }
        } else if (*cr).action as libc::c_uint == CONFIRM_CLOSE as libc::c_int as libc::c_uint {
            chan_read_failed(ssh, c);
            chan_write_failed(ssh, c);
        }
    }
    libc::free(cr as *mut libc::c_void);
}
unsafe extern "C" fn client_abandon_status_confirm(
    mut _ssh: *mut ssh,
    mut _c: *mut Channel,
    mut ctx: *mut libc::c_void,
) {
    libc::free(ctx);
}
pub unsafe extern "C" fn client_expect_confirm(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut request: *const libc::c_char,
    mut action: confirm_action,
) {
    let mut cr: *mut channel_reply_ctx = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<channel_reply_ctx>() as libc::c_ulong,
    ) as *mut channel_reply_ctx;
    (*cr).request_type = request;
    (*cr).action = action;
    channel_register_status_confirm(
        ssh,
        id,
        Some(
            client_status_confirm
                as unsafe extern "C" fn(
                    *mut ssh,
                    libc::c_int,
                    *mut Channel,
                    *mut libc::c_void,
                ) -> (),
        ),
        Some(
            client_abandon_status_confirm
                as unsafe extern "C" fn(*mut ssh, *mut Channel, *mut libc::c_void) -> (),
        ),
        cr as *mut libc::c_void,
    );
}
pub unsafe extern "C" fn client_register_global_confirm(
    mut cb: Option<global_confirm_cb>,
    mut ctx: *mut libc::c_void,
) {
    let mut gc: *mut global_confirm = 0 as *mut global_confirm;
    let mut last_gc: *mut global_confirm = 0 as *mut global_confirm;
    last_gc = *(*(global_confirms.tqh_last as *mut global_confirms)).tqh_last;
    if !last_gc.is_null() && (*last_gc).cb == cb && (*last_gc).ctx == ctx {
        (*last_gc).ref_count += 1;
        if (*last_gc).ref_count >= 2147483647 as libc::c_int {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                    b"client_register_global_confirm\0",
                ))
                .as_ptr(),
                735 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"last_gc->ref_count = %d\0" as *const u8 as *const libc::c_char,
                (*last_gc).ref_count,
            );
        }
        return;
    }
    gc = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<global_confirm>() as libc::c_ulong,
    ) as *mut global_confirm;
    (*gc).cb = cb;
    (*gc).ctx = ctx;
    (*gc).ref_count = 1 as libc::c_int;
    (*gc).entry.tqe_next = 0 as *mut global_confirm;
    (*gc).entry.tqe_prev = global_confirms.tqh_last;
    *global_confirms.tqh_last = gc;
    global_confirms.tqh_last = &mut (*gc).entry.tqe_next;
}
unsafe extern "C" fn can_update_hostkeys() -> libc::c_int {
    if hostkeys_update_complete != 0 {
        return 0 as libc::c_int;
    }
    if options.update_hostkeys == 2 as libc::c_int && options.batch_mode != 0 {
        return 0 as libc::c_int;
    }
    if options.update_hostkeys == 0
        || options.num_user_hostfiles <= 0 as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn client_repledge() {
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"client_repledge\0")).as_ptr(),
        766 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"enter\0" as *const u8 as *const libc::c_char,
    );
    if options.control_master != 0
        || !(options.control_path).is_null()
        || options.forward_x11 != 0
        || options.fork_after_authentication != 0
        || can_update_hostkeys() != 0
        || session_ident != -(1 as libc::c_int) && session_setup_complete == 0
    {
        return;
    }
    if options.num_local_forwards != 0 as libc::c_int
        || options.num_remote_forwards != 0 as libc::c_int
        || options.num_permitted_remote_opens != 0 as libc::c_int as libc::c_uint
        || options.enable_escape_commandline != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"client_repledge\0"))
                .as_ptr(),
            790 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"crate::openbsd_compat::bsd_misc::pledge: network\0" as *const u8
                as *const libc::c_char,
        );
        if crate::openbsd_compat::bsd_misc::pledge(
            b"stdio unix inet dns proc tty\0" as *const u8 as *const libc::c_char,
            0 as *mut *const libc::c_char,
        ) == -(1 as libc::c_int)
        {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"client_repledge\0"))
                    .as_ptr(),
                792 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::openbsd_compat::bsd_misc::pledge(): %s\0" as *const u8
                    as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
    } else if options.forward_agent != 0 as libc::c_int {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"client_repledge\0"))
                .as_ptr(),
            795 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"crate::openbsd_compat::bsd_misc::pledge: agent\0" as *const u8 as *const libc::c_char,
        );
        if crate::openbsd_compat::bsd_misc::pledge(
            b"stdio unix proc tty\0" as *const u8 as *const libc::c_char,
            0 as *mut *const libc::c_char,
        ) == -(1 as libc::c_int)
        {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"client_repledge\0"))
                    .as_ptr(),
                797 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::openbsd_compat::bsd_misc::pledge(): %s\0" as *const u8
                    as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
    } else {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"client_repledge\0"))
                .as_ptr(),
            799 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"crate::openbsd_compat::bsd_misc::pledge: libc::fork\0" as *const u8
                as *const libc::c_char,
        );
        if crate::openbsd_compat::bsd_misc::pledge(
            b"stdio proc tty\0" as *const u8 as *const libc::c_char,
            0 as *mut *const libc::c_char,
        ) == -(1 as libc::c_int)
        {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"client_repledge\0"))
                    .as_ptr(),
                801 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::openbsd_compat::bsd_misc::pledge(): %s\0" as *const u8
                    as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
    };
}
unsafe extern "C" fn process_cmdline(mut ssh: *mut ssh) {
    let mut current_block: u64;
    let mut handler: Option<unsafe extern "C" fn(libc::c_int) -> ()> = None;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cmd: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ok: libc::c_int = 0;
    let mut delete: libc::c_int = 0 as libc::c_int;
    let mut local: libc::c_int = 0 as libc::c_int;
    let mut remote: libc::c_int = 0 as libc::c_int;
    let mut dynamic: libc::c_int = 0 as libc::c_int;
    let mut fwd: Forward = Forward {
        listen_host: 0 as *mut libc::c_char,
        listen_port: 0,
        listen_path: 0 as *mut libc::c_char,
        connect_host: 0 as *mut libc::c_char,
        connect_port: 0,
        connect_path: 0 as *mut libc::c_char,
        allocated_port: 0,
        handle: 0,
    };
    memset(
        &mut fwd as *mut Forward as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<Forward>() as libc::c_ulong,
    );
    leave_raw_mode((options.request_tty == 3 as libc::c_int) as libc::c_int);
    handler = crate::misc::ssh_signal(
        2 as libc::c_int,
        ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
            1 as libc::c_int as libc::intptr_t,
        ),
    );
    s = read_passphrase(
        b"\r\nssh> \0" as *const u8 as *const libc::c_char,
        0x1 as libc::c_int,
    );
    cmd = s;
    if !s.is_null() {
        while *(*__ctype_b_loc()).offset(*s as u_char as libc::c_int as isize) as libc::c_int
            & _ISspace as libc::c_int as libc::c_ushort as libc::c_int
            != 0
        {
            s = s.offset(1);
            s;
        }
        if *s as libc::c_int == '-' as i32 {
            s = s.offset(1);
            s;
        }
        if !(*s as libc::c_int == '\0' as i32) {
            if *s as libc::c_int == 'h' as i32
                || *s as libc::c_int == 'H' as i32
                || *s as libc::c_int == '?' as i32
            {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"process_cmdline\0",
                    ))
                    .as_ptr(),
                    835 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"Commands:\0" as *const u8 as *const libc::c_char,
                );
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"process_cmdline\0",
                    ))
                    .as_ptr(),
                    837 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"      -L[bind_address:]port:host:hostport    Request local forward\0"
                        as *const u8 as *const libc::c_char,
                );
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"process_cmdline\0",
                    ))
                    .as_ptr(),
                    839 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"      -R[bind_address:]port:host:hostport    Request remote forward\0"
                        as *const u8 as *const libc::c_char,
                );
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"process_cmdline\0",
                    ))
                    .as_ptr(),
                    841 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"      -D[bind_address:]port                  Request dynamic forward\0"
                        as *const u8 as *const libc::c_char,
                );
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"process_cmdline\0",
                    ))
                    .as_ptr(),
                    843 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"      -KL[bind_address:]port                 Cancel local forward\0"
                        as *const u8 as *const libc::c_char,
                );
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"process_cmdline\0",
                    ))
                    .as_ptr(),
                    845 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"      -KR[bind_address:]port                 Cancel remote forward\0"
                        as *const u8 as *const libc::c_char,
                );
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"process_cmdline\0",
                    ))
                    .as_ptr(),
                    847 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"      -KD[bind_address:]port                 Cancel dynamic forward\0"
                        as *const u8 as *const libc::c_char,
                );
                if !(options.permit_local_command == 0) {
                    crate::log::sshlog(
                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"process_cmdline\0",
                        ))
                        .as_ptr(),
                        851 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        0 as *const libc::c_char,
                        b"      !args                                  Execute local command\0"
                            as *const u8 as *const libc::c_char,
                    );
                }
            } else if *s as libc::c_int == '!' as i32 && options.permit_local_command != 0 {
                s = s.offset(1);
                s;
                ssh_local_cmd(s);
            } else {
                if *s as libc::c_int == 'K' as i32 {
                    delete = 1 as libc::c_int;
                    s = s.offset(1);
                    s;
                }
                if *s as libc::c_int == 'L' as i32 {
                    local = 1 as libc::c_int;
                    current_block = 15345278821338558188;
                } else if *s as libc::c_int == 'R' as i32 {
                    remote = 1 as libc::c_int;
                    current_block = 15345278821338558188;
                } else if *s as libc::c_int == 'D' as i32 {
                    dynamic = 1 as libc::c_int;
                    current_block = 15345278821338558188;
                } else {
                    crate::log::sshlog(
                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"process_cmdline\0",
                        ))
                        .as_ptr(),
                        872 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        0 as *const libc::c_char,
                        b"Invalid command.\0" as *const u8 as *const libc::c_char,
                    );
                    current_block = 11516140394472427919;
                }
                match current_block {
                    11516140394472427919 => {}
                    _ => {
                        loop {
                            s = s.offset(1);
                            if !(*(*__ctype_b_loc()).offset(*s as u_char as libc::c_int as isize)
                                as libc::c_int
                                & _ISspace as libc::c_int as libc::c_ushort as libc::c_int
                                != 0)
                            {
                                break;
                            }
                        }
                        if delete != 0 {
                            if parse_forward(&mut fwd, s, 1 as libc::c_int, 0 as libc::c_int) == 0 {
                                crate::log::sshlog(
                                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"process_cmdline\0",
                                    ))
                                    .as_ptr(),
                                    883 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_INFO,
                                    0 as *const libc::c_char,
                                    b"Bad forwarding close specification.\0" as *const u8
                                        as *const libc::c_char,
                                );
                            } else {
                                if remote != 0 {
                                    ok = (channel_request_rforward_cancel(ssh, &mut fwd)
                                        == 0 as libc::c_int)
                                        as libc::c_int;
                                } else if dynamic != 0 {
                                    ok = (channel_cancel_lport_listener(
                                        ssh,
                                        &mut fwd,
                                        0 as libc::c_int,
                                        &mut options.fwd_opts,
                                    ) > 0 as libc::c_int)
                                        as libc::c_int;
                                } else {
                                    ok = (channel_cancel_lport_listener(
                                        ssh,
                                        &mut fwd,
                                        -(1 as libc::c_int),
                                        &mut options.fwd_opts,
                                    ) > 0 as libc::c_int)
                                        as libc::c_int;
                                }
                                if ok == 0 {
                                    crate::log::sshlog(
                                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                            b"process_cmdline\0",
                                        ))
                                        .as_ptr(),
                                        896 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_INFO,
                                        0 as *const libc::c_char,
                                        b"Unknown port forwarding.\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                } else {
                                    crate::log::sshlog(
                                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                            b"process_cmdline\0",
                                        ))
                                        .as_ptr(),
                                        899 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_INFO,
                                        0 as *const libc::c_char,
                                        b"Canceled forwarding.\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                }
                            }
                        } else {
                            if remote != 0 {
                                if parse_forward(&mut fwd, s, 0 as libc::c_int, remote) == 0
                                    && parse_forward(&mut fwd, s, 1 as libc::c_int, remote) == 0
                                {
                                    crate::log::sshlog(
                                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                            b"process_cmdline\0",
                                        ))
                                        .as_ptr(),
                                        905 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_INFO,
                                        0 as *const libc::c_char,
                                        b"Bad remote forwarding specification.\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                    current_block = 11516140394472427919;
                                } else {
                                    current_block = 6717214610478484138;
                                }
                            } else if parse_forward(&mut fwd, s, dynamic, remote) == 0 {
                                crate::log::sshlog(
                                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"process_cmdline\0",
                                    ))
                                    .as_ptr(),
                                    909 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_INFO,
                                    0 as *const libc::c_char,
                                    b"Bad local forwarding specification.\0" as *const u8
                                        as *const libc::c_char,
                                );
                                current_block = 11516140394472427919;
                            } else {
                                current_block = 6717214610478484138;
                            }
                            match current_block {
                                11516140394472427919 => {}
                                _ => {
                                    if local != 0 || dynamic != 0 {
                                        if channel_setup_local_fwd_listener(
                                            ssh,
                                            &mut fwd,
                                            &mut options.fwd_opts,
                                        ) == 0
                                        {
                                            crate::log::sshlog(
                                                b"clientloop.c\0" as *const u8
                                                    as *const libc::c_char,
                                                (*::core::mem::transmute::<
                                                    &[u8; 16],
                                                    &[libc::c_char; 16],
                                                >(
                                                    b"process_cmdline\0"
                                                ))
                                                .as_ptr(),
                                                915 as libc::c_int,
                                                0 as libc::c_int,
                                                SYSLOG_LEVEL_INFO,
                                                0 as *const libc::c_char,
                                                b"Port forwarding failed.\0" as *const u8
                                                    as *const libc::c_char,
                                            );
                                            current_block = 11516140394472427919;
                                        } else {
                                            current_block = 11777552016271000781;
                                        }
                                    } else if channel_request_remote_forwarding(ssh, &mut fwd)
                                        < 0 as libc::c_int
                                    {
                                        crate::log::sshlog(
                                            b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 16],
                                                &[libc::c_char; 16],
                                            >(
                                                b"process_cmdline\0"
                                            ))
                                            .as_ptr(),
                                            920 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_INFO,
                                            0 as *const libc::c_char,
                                            b"Port forwarding failed.\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        current_block = 11516140394472427919;
                                    } else {
                                        current_block = 11777552016271000781;
                                    }
                                    match current_block {
                                        11516140394472427919 => {}
                                        _ => {
                                            crate::log::sshlog(
                                                b"clientloop.c\0" as *const u8
                                                    as *const libc::c_char,
                                                (*::core::mem::transmute::<
                                                    &[u8; 16],
                                                    &[libc::c_char; 16],
                                                >(
                                                    b"process_cmdline\0"
                                                ))
                                                .as_ptr(),
                                                924 as libc::c_int,
                                                0 as libc::c_int,
                                                SYSLOG_LEVEL_INFO,
                                                0 as *const libc::c_char,
                                                b"Forwarding port.\0" as *const u8
                                                    as *const libc::c_char,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    crate::misc::ssh_signal(2 as libc::c_int, handler);
    enter_raw_mode((options.request_tty == 3 as libc::c_int) as libc::c_int);
    libc::free(cmd as *mut libc::c_void);
    libc::free(fwd.listen_host as *mut libc::c_void);
    libc::free(fwd.listen_path as *mut libc::c_void);
    libc::free(fwd.connect_host as *mut libc::c_void);
    libc::free(fwd.connect_path as *mut libc::c_void);
}
static mut esc_txt: [escape_help_text; 10] = [
    {
        let mut init = escape_help_text {
            cmd: b".\0" as *const u8 as *const libc::c_char,
            text: b"terminate session\0" as *const u8 as *const libc::c_char,
            flags: 2 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = escape_help_text {
            cmd: b".\0" as *const u8 as *const libc::c_char,
            text: b"terminate connection (and any multiplexed sessions)\0" as *const u8
                as *const libc::c_char,
            flags: 1 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = escape_help_text {
            cmd: b"B\0" as *const u8 as *const libc::c_char,
            text: b"send a BREAK to the remote system\0" as *const u8 as *const libc::c_char,
            flags: 0 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = escape_help_text {
            cmd: b"C\0" as *const u8 as *const libc::c_char,
            text: b"open a command line\0" as *const u8 as *const libc::c_char,
            flags: (1 as libc::c_int | 8 as libc::c_int) as libc::c_uint,
        };
        init
    },
    {
        let mut init = escape_help_text {
            cmd: b"R\0" as *const u8 as *const libc::c_char,
            text: b"request rekey\0" as *const u8 as *const libc::c_char,
            flags: 0 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = escape_help_text {
            cmd: b"V/v\0" as *const u8 as *const libc::c_char,
            text: b"decrease/increase verbosity (LogLevel)\0" as *const u8 as *const libc::c_char,
            flags: 1 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = escape_help_text {
            cmd: b"^Z\0" as *const u8 as *const libc::c_char,
            text: b"suspend ssh\0" as *const u8 as *const libc::c_char,
            flags: 1 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = escape_help_text {
            cmd: b"#\0" as *const u8 as *const libc::c_char,
            text: b"list forwarded connections\0" as *const u8 as *const libc::c_char,
            flags: 0 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = escape_help_text {
            cmd: b"&\0" as *const u8 as *const libc::c_char,
            text: b"background ssh (when waiting for connections to terminate)\0" as *const u8
                as *const libc::c_char,
            flags: 1 as libc::c_int as libc::c_uint,
        };
        init
    },
    {
        let mut init = escape_help_text {
            cmd: b"?\0" as *const u8 as *const libc::c_char,
            text: b"this message\0" as *const u8 as *const libc::c_char,
            flags: 0 as libc::c_int as libc::c_uint,
        };
        init
    },
];
unsafe extern "C" fn print_escape_help(
    mut b: *mut crate::sshbuf::sshbuf,
    mut escape_char: libc::c_int,
    mut mux_client: libc::c_int,
    mut using_stderr: libc::c_int,
) {
    let mut i: libc::c_uint = 0;
    let mut suppress_flags: libc::c_uint = 0;
    let mut r: libc::c_int = 0;
    r = sshbuf_putf(
        b,
        b"%c?\r\nSupported escape sequences:\r\n\0" as *const u8 as *const libc::c_char,
        escape_char,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"print_escape_help\0"))
                .as_ptr(),
            972 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
        );
    }
    suppress_flags = ((if mux_client != 0 {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    }) | (if mux_client != 0 {
        0 as libc::c_int
    } else {
        2 as libc::c_int
    }) | (if using_stderr != 0 {
        0 as libc::c_int
    } else {
        4 as libc::c_int
    }) | (if options.enable_escape_commandline == 0 as libc::c_int {
        8 as libc::c_int
    } else {
        0 as libc::c_int
    })) as libc::c_uint;
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (::core::mem::size_of::<[escape_help_text; 10]>() as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<escape_help_text>() as libc::c_ulong)
    {
        if !(esc_txt[i as usize].flags & suppress_flags != 0) {
            r = sshbuf_putf(
                b,
                b" %c%-3s - %s\r\n\0" as *const u8 as *const libc::c_char,
                escape_char,
                esc_txt[i as usize].cmd,
                esc_txt[i as usize].text,
            );
            if r != 0 as libc::c_int {
                sshfatal(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"print_escape_help\0",
                    ))
                    .as_ptr(),
                    985 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
                );
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    r = sshbuf_putf(
        b,
        b" %c%c   - send the escape character by typing it twice\r\n(Note that escapes are only recognized immediately after newline.)\r\n\0"
            as *const u8 as *const libc::c_char,
        escape_char,
        escape_char,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"print_escape_help\0"))
                .as_ptr(),
            992 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn process_escapes(
    mut ssh: *mut ssh,
    mut c: *mut Channel,
    mut bin: *mut crate::sshbuf::sshbuf,
    mut bout: *mut crate::sshbuf::sshbuf,
    mut berr: *mut crate::sshbuf::sshbuf,
    mut buf: *mut libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut b: [libc::c_char; 16] = [0; 16];
    let mut current_block: u64;
    let mut pid: pid_t = 0;
    let mut r: libc::c_int = 0;
    let mut bytes: libc::c_int = 0 as libc::c_int;
    let mut i: u_int = 0;
    let mut ch: u_char = 0;
    let mut s: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut efc: *mut escape_filter_ctx = 0 as *mut escape_filter_ctx;
    if c.is_null() || ((*c).filter_ctx).is_null() || len <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    efc = (*c).filter_ctx as *mut escape_filter_ctx;
    i = 0 as libc::c_int as u_int;
    while i < len as u_int {
        ch = *buf.offset(i as isize) as u_char;
        if (*efc).escape_pending != 0 {
            (*efc).escape_pending = 0 as libc::c_int;
            match ch as libc::c_int {
                46 => {
                    r = sshbuf_putf(
                        berr,
                        b"%c.\r\n\0" as *const u8 as *const libc::c_char,
                        (*efc).escape_char,
                    );
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"clientloop.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"process_escapes\0",
                            ))
                            .as_ptr(),
                            1030 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    if !c.is_null() && (*c).ctl_chan != -(1 as libc::c_int) {
                        channel_force_close(ssh, c, 1 as libc::c_int);
                        return 0 as libc::c_int;
                    } else {
                        ::core::ptr::write_volatile(
                            &mut quit_pending as *mut sig_atomic_t,
                            1 as libc::c_int,
                        );
                    }
                    return -(1 as libc::c_int);
                }
                26 => {
                    if !c.is_null() && (*c).ctl_chan != -(1 as libc::c_int) {
                        b = [0; 16];
                        current_block = 12169762034934395020;
                    } else {
                        r = sshbuf_putf(
                            berr,
                            b"%c^Z [suspend ssh]\r\n\0" as *const u8 as *const libc::c_char,
                            (*efc).escape_char,
                        );
                        if r != 0 as libc::c_int {
                            sshfatal(
                                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                    b"process_escapes\0",
                                ))
                                .as_ptr(),
                                1058 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                ssh_err(r),
                                b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
                            );
                        }
                        client_suspend_self(bin, bout, berr);
                        current_block = 820271813250567934;
                    }
                }
                66 => {
                    r = sshbuf_putf(
                        berr,
                        b"%cB\r\n\0" as *const u8 as *const libc::c_char,
                        (*efc).escape_char,
                    );
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"clientloop.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"process_escapes\0",
                            ))
                            .as_ptr(),
                            1069 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    channel_request_start(
                        ssh,
                        (*c).self_0,
                        b"break\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                        0 as libc::c_int,
                    );
                    r = sshpkt_put_u32(ssh, 1000 as libc::c_int as u_int32_t);
                    if r != 0 as libc::c_int || {
                        r = sshpkt_send(ssh);
                        r != 0 as libc::c_int
                    } {
                        sshfatal(
                            b"clientloop.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"process_escapes\0",
                            ))
                            .as_ptr(),
                            1073 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"send packet\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    current_block = 820271813250567934;
                }
                82 => {
                    if (*ssh).compat & 0x8000 as libc::c_int != 0 {
                        crate::log::sshlog(
                            b"clientloop.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"process_escapes\0",
                            ))
                            .as_ptr(),
                            1079 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_INFO,
                            0 as *const libc::c_char,
                            b"Server does not support re-keying\0" as *const u8
                                as *const libc::c_char,
                        );
                    } else {
                        need_rekeying = 1 as libc::c_int;
                    }
                    current_block = 820271813250567934;
                }
                86 | 118 => {
                    if !c.is_null() && (*c).ctl_chan != -(1 as libc::c_int) {
                        current_block = 12169762034934395020;
                    } else {
                        if log_is_on_stderr() == 0 {
                            r = sshbuf_putf(
                                berr,
                                b"%c%c [Logging to syslog]\r\n\0" as *const u8
                                    as *const libc::c_char,
                                (*efc).escape_char,
                                ch as libc::c_int,
                            );
                            if r != 0 as libc::c_int {
                                sshfatal(
                                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"process_escapes\0",
                                    ))
                                    .as_ptr(),
                                    1093 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
                                );
                            }
                        } else {
                            if ch as libc::c_int == 'V' as i32
                                && options.log_level as libc::c_int
                                    > SYSLOG_LEVEL_QUIET as libc::c_int
                            {
                                options.log_level -= 1;
                                log_change_level(options.log_level);
                            }
                            if ch as libc::c_int == 'v' as i32
                                && (options.log_level as libc::c_int)
                                    < SYSLOG_LEVEL_DEBUG3 as libc::c_int
                            {
                                options.log_level += 1;
                                log_change_level(options.log_level);
                            }
                            r = sshbuf_putf(
                                berr,
                                b"%c%c [LogLevel %s]\r\n\0" as *const u8 as *const libc::c_char,
                                (*efc).escape_char,
                                ch as libc::c_int,
                                log_level_name(options.log_level),
                            );
                            if r != 0 as libc::c_int {
                                sshfatal(
                                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"process_escapes\0",
                                    ))
                                    .as_ptr(),
                                    1106 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
                                );
                            }
                        }
                        current_block = 820271813250567934;
                    }
                }
                38 => {
                    if (*c).ctl_chan != -(1 as libc::c_int) {
                        current_block = 12169762034934395020;
                    } else {
                        leave_raw_mode((options.request_tty == 3 as libc::c_int) as libc::c_int);
                        channel_stop_listening(ssh);
                        r = sshbuf_putf(
                            berr,
                            b"%c& [backgrounded]\n\0" as *const u8 as *const libc::c_char,
                            (*efc).escape_char,
                        );
                        if r != 0 as libc::c_int {
                            sshfatal(
                                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                    b"process_escapes\0",
                                ))
                                .as_ptr(),
                                1126 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                ssh_err(r),
                                b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
                            );
                        }
                        pid = libc::fork();
                        if pid == -(1 as libc::c_int) {
                            crate::log::sshlog(
                                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                    b"process_escapes\0",
                                ))
                                .as_ptr(),
                                1131 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"libc::fork: %.100s\0" as *const u8 as *const libc::c_char,
                                libc::strerror(*libc::__errno_location()),
                            );
                        } else {
                            if pid != 0 as libc::c_int {
                                libc::exit(0 as libc::c_int);
                            }
                            r = sshbuf_put_u8(bin, 4 as libc::c_int as u_char);
                            if r != 0 as libc::c_int {
                                sshfatal(
                                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"process_escapes\0",
                                    ))
                                    .as_ptr(),
                                    1141 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"sshbuf_put_u8\0" as *const u8 as *const libc::c_char,
                                );
                            }
                            return -(1 as libc::c_int);
                        }
                        current_block = 820271813250567934;
                    }
                }
                63 => {
                    print_escape_help(
                        berr,
                        (*efc).escape_char,
                        (!c.is_null() && (*c).ctl_chan != -(1 as libc::c_int)) as libc::c_int,
                        log_is_on_stderr(),
                    );
                    current_block = 820271813250567934;
                }
                35 => {
                    r = sshbuf_putf(
                        berr,
                        b"%c#\r\n\0" as *const u8 as *const libc::c_char,
                        (*efc).escape_char,
                    );
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"clientloop.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"process_escapes\0",
                            ))
                            .as_ptr(),
                            1152 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    s = channel_open_message(ssh);
                    r = sshbuf_put(berr, s as *const libc::c_void, strlen(s));
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"clientloop.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"process_escapes\0",
                            ))
                            .as_ptr(),
                            1155 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"sshbuf_put\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    libc::free(s as *mut libc::c_void);
                    current_block = 820271813250567934;
                }
                67 => {
                    if !c.is_null() && (*c).ctl_chan != -(1 as libc::c_int) {
                        current_block = 12169762034934395020;
                    } else {
                        if options.enable_escape_commandline == 0 as libc::c_int {
                            r = sshbuf_putf(
                                berr,
                                b"commandline disabled\r\n\0" as *const u8 as *const libc::c_char,
                            );
                            if r != 0 as libc::c_int {
                                sshfatal(
                                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"process_escapes\0",
                                    ))
                                    .as_ptr(),
                                    1165 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    ssh_err(r),
                                    b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
                                );
                            }
                        } else {
                            process_cmdline(ssh);
                        }
                        current_block = 820271813250567934;
                    }
                }
                _ => {
                    if ch as libc::c_int != (*efc).escape_char {
                        r = sshbuf_put_u8(bin, (*efc).escape_char as u_char);
                        if r != 0 as libc::c_int {
                            sshfatal(
                                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                    b"process_escapes\0",
                                ))
                                .as_ptr(),
                                1175 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                ssh_err(r),
                                b"sshbuf_put_u8\0" as *const u8 as *const libc::c_char,
                            );
                        }
                        bytes += 1;
                        bytes;
                    }
                    current_block = 13484060386966298149;
                }
            }
            match current_block {
                820271813250567934 => {}
                13484060386966298149 => {}
                _ => {
                    if ch as libc::c_int == 'Z' as i32 - 64 as libc::c_int {
                        libc::snprintf(
                            b.as_mut_ptr(),
                            ::core::mem::size_of::<[libc::c_char; 16]>() as usize,
                            b"^Z\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        libc::snprintf(
                            b.as_mut_ptr(),
                            ::core::mem::size_of::<[libc::c_char; 16]>() as usize,
                            b"%c\0" as *const u8 as *const libc::c_char,
                            ch as libc::c_int,
                        );
                    }
                    r = sshbuf_putf(
                        berr,
                        b"%c%s escape not available to multiplexed sessions\r\n\0" as *const u8
                            as *const libc::c_char,
                        (*efc).escape_char,
                        b.as_mut_ptr(),
                    );
                    if r != 0 as libc::c_int {
                        sshfatal(
                            b"clientloop.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"process_escapes\0",
                            ))
                            .as_ptr(),
                            1051 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            ssh_err(r),
                            b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    current_block = 820271813250567934;
                }
            }
        } else if last_was_cr != 0 && ch as libc::c_int == (*efc).escape_char {
            (*efc).escape_pending = 1 as libc::c_int;
            current_block = 820271813250567934;
        } else {
            current_block = 13484060386966298149;
        }
        match current_block {
            13484060386966298149 => {
                last_was_cr = (ch as libc::c_int == '\r' as i32 || ch as libc::c_int == '\n' as i32)
                    as libc::c_int;
                r = sshbuf_put_u8(bin, ch);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"process_escapes\0",
                        ))
                        .as_ptr(),
                        1202 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"sshbuf_put_u8\0" as *const u8 as *const libc::c_char,
                    );
                }
                bytes += 1;
                bytes;
            }
            _ => {}
        }
        i = i.wrapping_add(1);
        i;
    }
    return bytes;
}
unsafe extern "C" fn client_process_buffered_input_packets(mut ssh: *mut ssh) {
    ssh_dispatch_run_fatal(ssh, DISPATCH_NONBLOCK as libc::c_int, &mut quit_pending);
}
pub unsafe extern "C" fn client_new_escape_filter_ctx(
    mut escape_char: libc::c_int,
) -> *mut libc::c_void {
    let mut ret: *mut escape_filter_ctx = 0 as *mut escape_filter_ctx;
    ret = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<escape_filter_ctx>() as libc::c_ulong,
    ) as *mut escape_filter_ctx;
    (*ret).escape_pending = 0 as libc::c_int;
    (*ret).escape_char = escape_char;
    return ret as *mut libc::c_void;
}
pub unsafe extern "C" fn client_filter_cleanup(
    mut _ssh: *mut ssh,
    mut _cid: libc::c_int,
    mut ctx: *mut libc::c_void,
) {
    libc::free(ctx);
}
pub unsafe extern "C" fn client_simple_escape_filter(
    mut ssh: *mut ssh,
    mut c: *mut Channel,
    mut buf: *mut libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    if (*c).extended_usage != 2 as libc::c_int {
        return 0 as libc::c_int;
    }
    return process_escapes(ssh, c, (*c).input, (*c).output, (*c).extended, buf, len);
}
unsafe extern "C" fn client_channel_closed(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut _force: libc::c_int,
    mut _arg: *mut libc::c_void,
) {
    channel_cancel_cleanup(ssh, id);
    session_closed = 1 as libc::c_int;
    leave_raw_mode((options.request_tty == 3 as libc::c_int) as libc::c_int);
}
pub unsafe extern "C" fn client_loop(
    mut ssh: *mut ssh,
    mut have_pty: libc::c_int,
    mut escape_char_arg: libc::c_int,
    mut ssh2_chan_id: libc::c_int,
) -> libc::c_int {
    let mut pfd: *mut pollfd = 0 as *mut pollfd;
    let mut npfd_alloc: u_int = 0 as libc::c_int as u_int;
    let mut npfd_active: u_int = 0 as libc::c_int as u_int;
    let mut start_time: libc::c_double = 0.;
    let mut total_time: libc::c_double = 0.;
    let mut r: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut ibytes: u_int64_t = 0;
    let mut obytes: u_int64_t = 0;
    let mut conn_in_ready: libc::c_int = 0;
    let mut conn_out_ready: libc::c_int = 0;
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0")).as_ptr(),
        1282 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Entering interactive session.\0" as *const u8 as *const libc::c_char,
    );
    session_ident = ssh2_chan_id;
    if options.control_master != 0 && option_clear_or_none(options.control_path) == 0 {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0")).as_ptr(),
            1287 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"crate::openbsd_compat::bsd_misc::pledge: id\0" as *const u8 as *const libc::c_char,
        );
        if crate::openbsd_compat::bsd_misc::pledge(
            b"stdio rpath wpath cpath unix inet dns recvfd sendfd proc exec id tty\0" as *const u8
                as *const libc::c_char,
            0 as *mut *const libc::c_char,
        ) == -(1 as libc::c_int)
        {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0"))
                    .as_ptr(),
                1290 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::openbsd_compat::bsd_misc::pledge(): %s\0" as *const u8
                    as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
    } else if options.forward_x11 != 0 || options.permit_local_command != 0 {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0")).as_ptr(),
            1293 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"crate::openbsd_compat::bsd_misc::pledge: exec\0" as *const u8 as *const libc::c_char,
        );
        if crate::openbsd_compat::bsd_misc::pledge(
            b"stdio rpath wpath cpath unix inet dns proc exec tty\0" as *const u8
                as *const libc::c_char,
            0 as *mut *const libc::c_char,
        ) == -(1 as libc::c_int)
        {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0"))
                    .as_ptr(),
                1296 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::openbsd_compat::bsd_misc::pledge(): %s\0" as *const u8
                    as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
    } else if options.update_hostkeys != 0 {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0")).as_ptr(),
            1299 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"crate::openbsd_compat::bsd_misc::pledge: filesystem\0" as *const u8
                as *const libc::c_char,
        );
        if crate::openbsd_compat::bsd_misc::pledge(
            b"stdio rpath wpath cpath unix inet dns proc tty\0" as *const u8 as *const libc::c_char,
            0 as *mut *const libc::c_char,
        ) == -(1 as libc::c_int)
        {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0"))
                    .as_ptr(),
                1302 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::openbsd_compat::bsd_misc::pledge(): %s\0" as *const u8
                    as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
    } else if option_clear_or_none(options.proxy_command) == 0
        || options.fork_after_authentication != 0
    {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0")).as_ptr(),
            1306 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"crate::openbsd_compat::bsd_misc::pledge: proc\0" as *const u8 as *const libc::c_char,
        );
        if crate::openbsd_compat::bsd_misc::pledge(
            b"stdio cpath unix inet dns proc tty\0" as *const u8 as *const libc::c_char,
            0 as *mut *const libc::c_char,
        ) == -(1 as libc::c_int)
        {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0"))
                    .as_ptr(),
                1308 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::openbsd_compat::bsd_misc::pledge(): %s\0" as *const u8
                    as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
    } else {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0")).as_ptr(),
            1311 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"crate::openbsd_compat::bsd_misc::pledge: network\0" as *const u8
                as *const libc::c_char,
        );
        if crate::openbsd_compat::bsd_misc::pledge(
            b"stdio unix inet dns proc tty\0" as *const u8 as *const libc::c_char,
            0 as *mut *const libc::c_char,
        ) == -(1 as libc::c_int)
        {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0"))
                    .as_ptr(),
                1313 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::openbsd_compat::bsd_misc::pledge(): %s\0" as *const u8
                    as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
    }
    client_repledge();
    start_time = monotime_double();
    last_was_cr = 1 as libc::c_int;
    exit_status = -(1 as libc::c_int);
    connection_in = ssh_packet_get_connection_in(ssh);
    connection_out = ssh_packet_get_connection_out(ssh);
    ::core::ptr::write_volatile(&mut quit_pending as *mut sig_atomic_t, 0 as libc::c_int);
    stderr_buffer = crate::sshbuf::sshbuf_new();
    if stderr_buffer.is_null() {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0")).as_ptr(),
            1331 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    client_init_dispatch(ssh);
    if crate::misc::ssh_signal(
        1 as libc::c_int,
        ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
            1 as libc::c_int as libc::intptr_t,
        ),
    ) != ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
        1 as libc::c_int as libc::intptr_t,
    ) {
        crate::misc::ssh_signal(
            1 as libc::c_int,
            Some(signal_handler as unsafe extern "C" fn(libc::c_int) -> ()),
        );
    }
    if crate::misc::ssh_signal(
        2 as libc::c_int,
        ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
            1 as libc::c_int as libc::intptr_t,
        ),
    ) != ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
        1 as libc::c_int as libc::intptr_t,
    ) {
        crate::misc::ssh_signal(
            2 as libc::c_int,
            Some(signal_handler as unsafe extern "C" fn(libc::c_int) -> ()),
        );
    }
    if crate::misc::ssh_signal(
        3 as libc::c_int,
        ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
            1 as libc::c_int as libc::intptr_t,
        ),
    ) != ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
        1 as libc::c_int as libc::intptr_t,
    ) {
        crate::misc::ssh_signal(
            3 as libc::c_int,
            Some(signal_handler as unsafe extern "C" fn(libc::c_int) -> ()),
        );
    }
    if crate::misc::ssh_signal(
        15 as libc::c_int,
        ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
            1 as libc::c_int as libc::intptr_t,
        ),
    ) != ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
        1 as libc::c_int as libc::intptr_t,
    ) {
        crate::misc::ssh_signal(
            15 as libc::c_int,
            Some(signal_handler as unsafe extern "C" fn(libc::c_int) -> ()),
        );
    }
    crate::misc::ssh_signal(
        28 as libc::c_int,
        Some(window_change_handler as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    if have_pty != 0 {
        enter_raw_mode((options.request_tty == 3 as libc::c_int) as libc::c_int);
    }
    if session_ident != -(1 as libc::c_int) {
        if escape_char_arg != -(2 as libc::c_int) {
            channel_register_filter(
                ssh,
                session_ident,
                Some(
                    client_simple_escape_filter
                        as unsafe extern "C" fn(
                            *mut ssh,
                            *mut Channel,
                            *mut libc::c_char,
                            libc::c_int,
                        ) -> libc::c_int,
                ),
                None,
                Some(
                    client_filter_cleanup
                        as unsafe extern "C" fn(*mut ssh, libc::c_int, *mut libc::c_void) -> (),
                ),
                client_new_escape_filter_ctx(escape_char_arg),
            );
        }
        channel_register_cleanup(
            ssh,
            session_ident,
            Some(
                client_channel_closed
                    as unsafe extern "C" fn(
                        *mut ssh,
                        libc::c_int,
                        libc::c_int,
                        *mut libc::c_void,
                    ) -> (),
            ),
            0 as libc::c_int,
        );
    }
    schedule_server_alive_check();
    while quit_pending == 0 {
        client_process_buffered_input_packets(ssh);
        if session_closed != 0 && channel_still_open(ssh) == 0 {
            break;
        }
        if ssh_packet_is_rekeying(ssh) != 0 {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0"))
                    .as_ptr(),
                1376 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"rekeying in progress\0" as *const u8 as *const libc::c_char,
            );
        } else if need_rekeying != 0 {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0"))
                    .as_ptr(),
                1379 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"need rekeying\0" as *const u8 as *const libc::c_char,
            );
            r = kex_start_rekex(ssh);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0"))
                        .as_ptr(),
                    1381 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"kex_start_rekex\0" as *const u8 as *const libc::c_char,
                );
            }
            need_rekeying = 0 as libc::c_int;
        } else {
            if ssh_packet_not_very_much_data_to_write(ssh) != 0 {
                channel_output_poll(ssh);
            }
            client_check_window_change(ssh);
            if quit_pending != 0 {
                break;
            }
        }
        client_wait_until_can_do_something(
            ssh,
            &mut pfd,
            &mut npfd_alloc,
            &mut npfd_active,
            ssh_packet_is_rekeying(ssh),
            &mut conn_in_ready,
            &mut conn_out_ready,
        );
        if quit_pending != 0 {
            break;
        }
        channel_after_poll(ssh, pfd, npfd_active);
        if conn_in_ready != 0 {
            client_process_net_input(ssh);
        }
        if quit_pending != 0 {
            break;
        }
        r = ssh_packet_check_rekey(ssh);
        if r != 0 as libc::c_int {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0"))
                    .as_ptr(),
                1423 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"cannot start rekeying\0" as *const u8 as *const libc::c_char,
            );
        }
        if conn_out_ready != 0 {
            r = ssh_packet_write_poll(ssh);
            if r != 0 as libc::c_int {
                sshpkt_fatal(
                    ssh,
                    r,
                    b"%s: ssh_packet_write_poll\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0"))
                        .as_ptr(),
                );
            }
        }
        if !(control_persist_exit_time > 0 as libc::c_int as libc::c_long) {
            continue;
        }
        if !(monotime() >= control_persist_exit_time) {
            continue;
        }
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0")).as_ptr(),
            1443 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"ControlPersist timeout expired\0" as *const u8 as *const libc::c_char,
        );
        break;
    }
    libc::free(pfd as *mut libc::c_void);
    crate::misc::ssh_signal(28 as libc::c_int, None);
    r = sshpkt_start(ssh, 1 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_u32(ssh, 11 as libc::c_int as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_cstring(
                ssh,
                b"disconnected by user\0" as *const u8 as *const libc::c_char
                    as *const libc::c_void,
            );
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
        || {
            r = ssh_packet_write_wait(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0")).as_ptr(),
            1461 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send disconnect\0" as *const u8 as *const libc::c_char,
        );
    }
    channel_free_all(ssh);
    if have_pty != 0 {
        leave_raw_mode((options.request_tty == 3 as libc::c_int) as libc::c_int);
    }
    if options.session_type == 0 as libc::c_int && received_signal == 15 as libc::c_int {
        ::core::ptr::write_volatile(&mut received_signal as *mut sig_atomic_t, 0 as libc::c_int);
        exit_status = 0 as libc::c_int;
    }
    if received_signal != 0 {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0")).as_ptr(),
            1480 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"Killed by signal %d.\0" as *const u8 as *const libc::c_char,
            received_signal,
        );
        cleanup_exit(255 as libc::c_int);
    }
    if have_pty != 0 && options.log_level as libc::c_int >= SYSLOG_LEVEL_INFO as libc::c_int {
        quit_message(
            b"Connection to %s closed.\0" as *const u8 as *const libc::c_char,
            host,
        );
    }
    if sshbuf_len(stderr_buffer) > 0 as libc::c_int as libc::c_ulong {
        len = atomicio(
            ::core::mem::transmute::<
                Option<unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t>,
                Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
            >(Some(
                write as unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
            )),
            fileno(stderr),
            sshbuf_ptr(stderr_buffer) as *mut u_char as *mut libc::c_void,
            sshbuf_len(stderr_buffer),
        ) as libc::c_int;
        if len < 0 as libc::c_int || len as u_int as libc::c_ulong != sshbuf_len(stderr_buffer) {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0"))
                    .as_ptr(),
                1497 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Write failed flushing stderr buffer.\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = sshbuf_consume(stderr_buffer, len as size_t);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0"))
                        .as_ptr(),
                    1499 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"sshbuf_consume\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }
    sshbuf_free(stderr_buffer);
    total_time = monotime_double() - start_time;
    ssh_packet_get_bytes(ssh, &mut ibytes, &mut obytes);
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0")).as_ptr(),
        1509 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_VERBOSE,
        0 as *const libc::c_char,
        b"Transferred: sent %llu, received %llu bytes, in %.1f seconds\0" as *const u8
            as *const libc::c_char,
        obytes as libc::c_ulonglong,
        ibytes as libc::c_ulonglong,
        total_time,
    );
    if total_time > 0 as libc::c_int as libc::c_double {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0")).as_ptr(),
            1512 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"Bytes per second: sent %.1f, received %.1f\0" as *const u8 as *const libc::c_char,
            obytes as libc::c_double / total_time,
            ibytes as libc::c_double / total_time,
        );
    }
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"client_loop\0")).as_ptr(),
        1514 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Exit status %d\0" as *const u8 as *const libc::c_char,
        exit_status,
    );
    return exit_status;
}
unsafe extern "C" fn client_request_forwarded_tcpip(
    mut ssh: *mut ssh,
    mut request_type: *const libc::c_char,
    mut rchan: libc::c_int,
    mut rwindow: u_int,
    mut rmaxpack: u_int,
) -> *mut Channel {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut listen_address: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut originator_address: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut listen_port: u_int = 0;
    let mut originator_port: u_int = 0;
    let mut r: libc::c_int = 0;
    r = sshpkt_get_cstring(ssh, &mut listen_address, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_get_u32(ssh, &mut listen_port);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_cstring(ssh, &mut originator_address, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_u32(ssh, &mut originator_port);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                b"client_request_forwarded_tcpip\0",
            ))
            .as_ptr(),
            1536 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse packet\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
            b"client_request_forwarded_tcpip\0",
        ))
        .as_ptr(),
        1539 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"listen %s port %d, originator %s port %d\0" as *const u8 as *const libc::c_char,
        listen_address,
        listen_port,
        originator_address,
        originator_port,
    );
    if listen_port > 0xffff as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                b"client_request_forwarded_tcpip\0",
            ))
            .as_ptr(),
            1542 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"invalid listen port\0" as *const u8 as *const libc::c_char,
        );
    } else if originator_port > 0xffff as libc::c_int as libc::c_uint {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                b"client_request_forwarded_tcpip\0",
            ))
            .as_ptr(),
            1544 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"invalid originator port\0" as *const u8 as *const libc::c_char,
        );
    } else {
        c = channel_connect_by_listen_address(
            ssh,
            listen_address,
            listen_port as u_short,
            b"forwarded-tcpip\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            originator_address,
        );
    }
    if !c.is_null() && (*c).type_0 == 16 as libc::c_int {
        b = crate::sshbuf::sshbuf_new();
        if b.is_null() {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                    b"client_request_forwarded_tcpip\0",
                ))
                .as_ptr(),
                1553 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"alloc reply\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = sshbuf_put_u8(b, 0 as libc::c_int as u_char);
            if r != 0 as libc::c_int
                || {
                    r = sshbuf_put_u8(b, 90 as libc::c_int as u_char);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_cstring(b, request_type);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_u32(b, rchan as u_int32_t);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_u32(b, rwindow);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_u32(b, rmaxpack);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_cstring(b, listen_address);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_u32(b, listen_port);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_cstring(b, originator_address);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_u32(b, originator_port);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_stringb((*c).output, b);
                    r != 0 as libc::c_int
                }
            {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 31], &[libc::c_char; 31]>(
                        b"client_request_forwarded_tcpip\0",
                    ))
                    .as_ptr(),
                    1568 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"compose for muxclient\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }
    sshbuf_free(b);
    libc::free(originator_address as *mut libc::c_void);
    libc::free(listen_address as *mut libc::c_void);
    return c;
}
unsafe extern "C" fn client_request_forwarded_streamlocal(
    mut ssh: *mut ssh,
    mut _request_type: *const libc::c_char,
    mut _rchan: libc::c_int,
) -> *mut Channel {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut listen_path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    r = sshpkt_get_cstring(ssh, &mut listen_path, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_get_string(ssh, 0 as *mut *mut u_char, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                b"client_request_forwarded_streamlocal\0",
            ))
            .as_ptr(),
            1592 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse packet\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
            b"client_request_forwarded_streamlocal\0",
        ))
        .as_ptr(),
        1594 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"request: %s\0" as *const u8 as *const libc::c_char,
        listen_path,
    );
    c = channel_connect_by_listen_path(
        ssh,
        listen_path,
        b"forwarded-streamlocal@openssh.com\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        b"forwarded-streamlocal\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    );
    libc::free(listen_path as *mut libc::c_void);
    return c;
}
unsafe extern "C" fn client_request_x11(
    mut ssh: *mut ssh,
    mut _request_type: *const libc::c_char,
    mut _rchan: libc::c_int,
) -> *mut Channel {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut originator: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut originator_port: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut sock: libc::c_int = 0;
    if options.forward_x11 == 0 {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"client_request_x11\0"))
                .as_ptr(),
            1611 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Warning: ssh server tried X11 forwarding.\0" as *const u8 as *const libc::c_char,
        );
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"client_request_x11\0"))
                .as_ptr(),
            1613 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Warning: this is probably a break-in attempt by a malicious server.\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as *mut Channel;
    }
    if x11_refuse_time != 0 as libc::c_int as libc::c_long && monotime() >= x11_refuse_time {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"client_request_x11\0"))
                .as_ptr(),
            1618 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"Rejected X11 connection after ForwardX11Timeout expired\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as *mut Channel;
    }
    r = sshpkt_get_cstring(ssh, &mut originator, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_get_u32(ssh, &mut originator_port);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_end(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"client_request_x11\0"))
                .as_ptr(),
            1624 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse packet\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"client_request_x11\0"))
            .as_ptr(),
        1628 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"client_request_x11: request from %s %u\0" as *const u8 as *const libc::c_char,
        originator,
        originator_port,
    );
    libc::free(originator as *mut libc::c_void);
    sock = x11_connect_display(ssh);
    if sock < 0 as libc::c_int {
        return 0 as *mut Channel;
    }
    c = channel_new(
        ssh,
        b"x11\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        7 as libc::c_int,
        sock,
        sock,
        -(1 as libc::c_int),
        (64 as libc::c_int * (32 as libc::c_int * 1024 as libc::c_int)) as u_int,
        (16 as libc::c_int * 1024 as libc::c_int) as u_int,
        0 as libc::c_int,
        b"x11\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    (*c).force_drain = 1 as libc::c_int;
    return c;
}
unsafe extern "C" fn client_request_agent(
    mut ssh: *mut ssh,
    mut _request_type: *const libc::c_char,
    mut _rchan: libc::c_int,
) -> *mut Channel {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut r: libc::c_int = 0;
    let mut sock: libc::c_int = 0;
    if options.forward_agent == 0 {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"client_request_agent\0"))
                .as_ptr(),
            1647 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Warning: ssh server tried agent forwarding.\0" as *const u8 as *const libc::c_char,
        );
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"client_request_agent\0"))
                .as_ptr(),
            1649 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Warning: this is probably a break-in attempt by a malicious server.\0" as *const u8
                as *const libc::c_char,
        );
        return 0 as *mut Channel;
    }
    if forward_agent_sock_path.is_null() {
        r = ssh_get_authentication_socket(&mut sock);
    } else {
        r = ssh_get_authentication_socket_path(forward_agent_sock_path, &mut sock);
    }
    if r != 0 as libc::c_int {
        if r != -(47 as libc::c_int) {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(
                    b"client_request_agent\0",
                ))
                .as_ptr(),
                1659 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                ssh_err(r),
                b"ssh_get_authentication_socket\0" as *const u8 as *const libc::c_char,
            );
        }
        return 0 as *mut Channel;
    }
    r = ssh_agent_bind_hostkey(
        sock,
        (*(*ssh).kex).initial_hostkey,
        (*(*ssh).kex).session_id,
        (*(*ssh).kex).initial_sig,
        1 as libc::c_int,
    );
    if r == 0 as libc::c_int {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"client_request_agent\0"))
                .as_ptr(),
            1664 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"bound agent to hostkey\0" as *const u8 as *const libc::c_char,
        );
    } else {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"client_request_agent\0"))
                .as_ptr(),
            1666 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            ssh_err(r),
            b"ssh_agent_bind_hostkey\0" as *const u8 as *const libc::c_char,
        );
    }
    c = channel_new(
        ssh,
        b"authentication agent connection\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
        4 as libc::c_int,
        sock,
        sock,
        -(1 as libc::c_int),
        (4 as libc::c_int * (16 as libc::c_int * 1024 as libc::c_int)) as u_int,
        (32 as libc::c_int * 1024 as libc::c_int) as u_int,
        0 as libc::c_int,
        b"authentication agent connection\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    (*c).force_drain = 1 as libc::c_int;
    return c;
}
pub unsafe extern "C" fn client_request_tun_fwd(
    mut ssh: *mut ssh,
    mut tun_mode: libc::c_int,
    mut local_tun: libc::c_int,
    mut remote_tun: libc::c_int,
    mut cb: Option<channel_open_fn>,
    mut cbctx: *mut libc::c_void,
) -> *mut libc::c_char {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut r: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut ifname: *mut libc::c_char = 0 as *mut libc::c_char;
    if tun_mode == 0 as libc::c_int {
        return 0 as *mut libc::c_char;
    }
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"client_request_tun_fwd\0"))
            .as_ptr(),
        1687 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Requesting tun unit %d in mode %d\0" as *const u8 as *const libc::c_char,
        local_tun,
        tun_mode,
    );
    fd = tun_open(local_tun, tun_mode, &mut ifname);
    if fd == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"client_request_tun_fwd\0",
            ))
            .as_ptr(),
            1691 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Tunnel device open failed.\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut libc::c_char;
    }
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"client_request_tun_fwd\0"))
            .as_ptr(),
        1694 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Tunnel forwarding using interface %s\0" as *const u8 as *const libc::c_char,
        ifname,
    );
    c = channel_new(
        ssh,
        b"tun\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        3 as libc::c_int,
        fd,
        fd,
        -(1 as libc::c_int),
        (64 as libc::c_int * (32 as libc::c_int * 1024 as libc::c_int)) as u_int,
        (32 as libc::c_int * 1024 as libc::c_int) as u_int,
        0 as libc::c_int,
        b"tun\0" as *const u8 as *const libc::c_char,
        1 as libc::c_int,
    );
    (*c).datagram = 1 as libc::c_int;
    if options.tun_open == 0x1 as libc::c_int {
        channel_register_filter(
            ssh,
            (*c).self_0,
            Some(
                sys_tun_infilter
                    as unsafe extern "C" fn(
                        *mut ssh,
                        *mut Channel,
                        *mut libc::c_char,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
            Some(
                sys_tun_outfilter
                    as unsafe extern "C" fn(
                        *mut ssh,
                        *mut Channel,
                        *mut *mut u_char,
                        *mut size_t,
                    ) -> *mut u_char,
            ),
            None,
            0 as *mut libc::c_void,
        );
    }
    if cb.is_some() {
        channel_register_open_confirm(ssh, (*c).self_0, cb, cbctx);
    }
    r = sshpkt_start(ssh, 90 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_cstring(
                ssh,
                b"tun@openssh.com\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, (*c).self_0 as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, (*c).local_window_max);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, (*c).local_maxpacket);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, tun_mode as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_u32(ssh, remote_tun as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: send reply\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"client_request_tun_fwd\0",
            ))
            .as_ptr(),
        );
    }
    return ifname;
}
unsafe extern "C" fn client_input_channel_open(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut ctype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut rchan: u_int = 0;
    let mut len: size_t = 0;
    let mut rmaxpack: u_int = 0;
    let mut rwindow: u_int = 0;
    r = sshpkt_get_cstring(ssh, &mut ctype, &mut len);
    if !(r != 0 as libc::c_int
        || {
            r = sshpkt_get_u32(ssh, &mut rchan);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_u32(ssh, &mut rwindow);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_get_u32(ssh, &mut rmaxpack);
            r != 0 as libc::c_int
        })
    {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"client_input_channel_open\0",
            ))
            .as_ptr(),
            1740 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"client_input_channel_open: ctype %s rchan %d win %d max %d\0" as *const u8
                as *const libc::c_char,
            ctype,
            rchan,
            rwindow,
            rmaxpack,
        );
        if libc::strcmp(
            ctype,
            b"forwarded-tcpip\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            c = client_request_forwarded_tcpip(ssh, ctype, rchan as libc::c_int, rwindow, rmaxpack);
        } else if libc::strcmp(
            ctype,
            b"forwarded-streamlocal@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            c = client_request_forwarded_streamlocal(ssh, ctype, rchan as libc::c_int);
        } else if libc::strcmp(ctype, b"x11\0" as *const u8 as *const libc::c_char)
            == 0 as libc::c_int
        {
            c = client_request_x11(ssh, ctype, rchan as libc::c_int);
        } else if libc::strcmp(
            ctype,
            b"auth-agent@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            c = client_request_agent(ssh, ctype, rchan as libc::c_int);
        }
        if !c.is_null() && (*c).type_0 == 16 as libc::c_int {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"client_input_channel_open\0",
                ))
                .as_ptr(),
                1753 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"proxied to downstream: %s\0" as *const u8 as *const libc::c_char,
                ctype,
            );
        } else if !c.is_null() {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"client_input_channel_open\0",
                ))
                .as_ptr(),
                1755 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"confirm %s\0" as *const u8 as *const libc::c_char,
                ctype,
            );
            (*c).remote_id = rchan;
            (*c).have_remote_id = 1 as libc::c_int;
            (*c).remote_window = rwindow;
            (*c).remote_maxpacket = rmaxpack;
            if (*c).type_0 != 12 as libc::c_int {
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
                    sshpkt_fatal(
                        ssh,
                        r,
                        b"%s: send reply\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                            b"client_input_channel_open\0",
                        ))
                        .as_ptr(),
                    );
                }
            }
        } else {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"client_input_channel_open\0",
                ))
                .as_ptr(),
                1770 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"failure %s\0" as *const u8 as *const libc::c_char,
                ctype,
            );
            r = sshpkt_start(ssh, 92 as libc::c_int as u_char);
            if r != 0 as libc::c_int
                || {
                    r = sshpkt_put_u32(ssh, rchan);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_u32(ssh, 1 as libc::c_int as u_int32_t);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshpkt_put_cstring(
                        ssh,
                        b"open failed\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                    );
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
                sshpkt_fatal(
                    ssh,
                    r,
                    b"%s: send failure\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"client_input_channel_open\0",
                    ))
                    .as_ptr(),
                );
            }
        }
        r = 0 as libc::c_int;
    }
    libc::free(ctype as *mut libc::c_void);
    return r;
}
unsafe extern "C" fn client_input_channel_req(
    mut type_0: libc::c_int,
    mut seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut current_block: u64;
    let mut c: *mut Channel = 0 as *mut Channel;
    let mut rtype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut reply: u_char = 0;
    let mut id: u_int = 0;
    let mut exitval: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    r = sshpkt_get_u32(ssh, &mut id);
    if r != 0 as libc::c_int {
        return r;
    }
    if id <= 2147483647 as libc::c_int as libc::c_uint {
        c = channel_lookup(ssh, id as libc::c_int);
    }
    if channel_proxy_upstream(c, type_0, seq, ssh) != 0 {
        return 0 as libc::c_int;
    }
    r = sshpkt_get_cstring(ssh, &mut rtype, 0 as *mut size_t);
    if !(r != 0 as libc::c_int || {
        r = sshpkt_get_u8(ssh, &mut reply);
        r != 0 as libc::c_int
    }) {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"client_input_channel_req\0",
            ))
            .as_ptr(),
            1805 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"client_input_channel_req: channel %u rtype %s reply %d\0" as *const u8
                as *const libc::c_char,
            id,
            rtype,
            reply as libc::c_int,
        );
        if c.is_null() {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"client_input_channel_req\0",
                ))
                .as_ptr(),
                1809 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"client_input_channel_req: channel %d: unknown channel\0" as *const u8
                    as *const libc::c_char,
                id,
            );
            current_block = 17478428563724192186;
        } else if libc::strcmp(
            rtype,
            b"eow@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            r = sshpkt_get_end(ssh);
            if r != 0 as libc::c_int {
                current_block = 17569473009162609004;
            } else {
                chan_rcvd_eow(ssh, c);
                current_block = 17478428563724192186;
            }
        } else if libc::strcmp(
            rtype,
            b"libc::exit-status\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            r = sshpkt_get_u32(ssh, &mut exitval);
            if r != 0 as libc::c_int {
                current_block = 17569473009162609004;
            } else {
                if (*c).ctl_chan != -(1 as libc::c_int) {
                    mux_exit_message(ssh, c, exitval as libc::c_int);
                    success = 1 as libc::c_int;
                } else if id as libc::c_int == session_ident {
                    success = 1 as libc::c_int;
                    exit_status = exitval as libc::c_int;
                } else {
                    crate::log::sshlog(
                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                            b"client_input_channel_req\0",
                        ))
                        .as_ptr(),
                        1827 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"no sink for libc::exit-status on channel %d\0" as *const u8
                            as *const libc::c_char,
                        id,
                    );
                }
                r = sshpkt_get_end(ssh);
                if r != 0 as libc::c_int {
                    current_block = 17569473009162609004;
                } else {
                    current_block = 17478428563724192186;
                }
            }
        } else {
            current_block = 17478428563724192186;
        }
        match current_block {
            17569473009162609004 => {}
            _ => {
                if reply as libc::c_int != 0 && !c.is_null() && (*c).flags & 0x1 as libc::c_int == 0
                {
                    if (*c).have_remote_id == 0 {
                        sshfatal(
                            b"clientloop.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"client_input_channel_req\0",
                            ))
                            .as_ptr(),
                            1834 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"channel %d: no remote_id\0" as *const u8 as *const libc::c_char,
                            (*c).self_0,
                        );
                    }
                    r = sshpkt_start(
                        ssh,
                        (if success != 0 {
                            99 as libc::c_int
                        } else {
                            100 as libc::c_int
                        }) as u_char,
                    );
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
                        sshpkt_fatal(
                            ssh,
                            r,
                            b"%s: send failure\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"client_input_channel_req\0",
                            ))
                            .as_ptr(),
                        );
                    }
                }
                r = 0 as libc::c_int;
            }
        }
    }
    libc::free(rtype as *mut libc::c_void);
    return r;
}
unsafe extern "C" fn hostkeys_update_ctx_free(mut ctx: *mut hostkeys_update_ctx) {
    let mut i: size_t = 0;
    if ctx.is_null() {
        return;
    }
    i = 0 as libc::c_int as size_t;
    while i < (*ctx).nkeys {
        sshkey_free(*((*ctx).keys).offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    libc::free((*ctx).keys as *mut libc::c_void);
    libc::free((*ctx).keys_match as *mut libc::c_void);
    libc::free((*ctx).keys_verified as *mut libc::c_void);
    i = 0 as libc::c_int as size_t;
    while i < (*ctx).nold {
        sshkey_free(*((*ctx).old_keys).offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    libc::free((*ctx).old_keys as *mut libc::c_void);
    libc::free((*ctx).host_str as *mut libc::c_void);
    libc::free((*ctx).ip_str as *mut libc::c_void);
    libc::free(ctx as *mut libc::c_void);
}
unsafe extern "C" fn hostspec_is_complex(mut hosts: *const libc::c_char) -> libc::c_int {
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    if !(libc::strchr(hosts, '*' as i32)).is_null() || !(libc::strchr(hosts, '?' as i32)).is_null()
    {
        return 1 as libc::c_int;
    }
    cp = libc::strchr(hosts, ',' as i32);
    if cp.is_null() {
        return 0 as libc::c_int;
    }
    if !(libc::strchr(cp.offset(1 as libc::c_int as isize), ',' as i32)).is_null() {
        return 1 as libc::c_int;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn hostkeys_find(
    mut l: *mut hostkey_foreach_line,
    mut _ctx: *mut libc::c_void,
) -> libc::c_int {
    let mut ctx: *mut hostkeys_update_ctx = _ctx as *mut hostkeys_update_ctx;
    let mut i: size_t = 0;
    let mut tmp: *mut *mut sshkey = 0 as *mut *mut sshkey;
    if ((*l).key).is_null() {
        return 0 as libc::c_int;
    }
    if (*l).status != 3 as libc::c_int as libc::c_uint {
        i = 0 as libc::c_int as size_t;
        while i < (*ctx).nkeys {
            if sshkey_equal((*l).key, *((*ctx).keys).offset(i as isize)) != 0 {
                (*ctx).other_name_seen = 1 as libc::c_int;
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"hostkeys_find\0"))
                        .as_ptr(),
                    1938 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"found %s key under different name/addr at %s:%ld\0" as *const u8
                        as *const libc::c_char,
                    sshkey_ssh_name(*((*ctx).keys).offset(i as isize)),
                    (*l).path,
                    (*l).linenum,
                );
                return 0 as libc::c_int;
            }
            i = i.wrapping_add(1);
            i;
        }
        return 0 as libc::c_int;
    }
    if (*l).marker != MRK_NONE as libc::c_int {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"hostkeys_find\0"))
                .as_ptr(),
            1948 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"hostkeys file %s:%ld has CA/revocation marker\0" as *const u8 as *const libc::c_char,
            (*l).path,
            (*l).linenum,
        );
        (*ctx).complex_hostspec = 1 as libc::c_int;
        return 0 as libc::c_int;
    }
    if !((*ctx).ip_str).is_null() && !(libc::strchr((*l).hosts, ',' as i32)).is_null() {
        if (*l).match_0 & 1 as libc::c_int as libc::c_uint == 0 as libc::c_int as libc::c_uint {
            (*ctx).other_name_seen = 1 as libc::c_int;
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"hostkeys_find\0"))
                    .as_ptr(),
                1959 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"found address %s against different hostname at %s:%ld\0" as *const u8
                    as *const libc::c_char,
                (*ctx).ip_str,
                (*l).path,
                (*l).linenum,
            );
            return 0 as libc::c_int;
        } else if (*l).match_0 & ((1 as libc::c_int) << 1 as libc::c_int) as libc::c_uint
            == 0 as libc::c_int as libc::c_uint
        {
            (*ctx).other_name_seen = 1 as libc::c_int;
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"hostkeys_find\0"))
                    .as_ptr(),
                1965 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"found hostname %s against different address at %s:%ld\0" as *const u8
                    as *const libc::c_char,
                (*ctx).host_str,
                (*l).path,
                (*l).linenum,
            );
        }
    }
    if hostspec_is_complex((*l).hosts) != 0 {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"hostkeys_find\0"))
                .as_ptr(),
            1975 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"hostkeys file %s:%ld complex host specification\0" as *const u8
                as *const libc::c_char,
            (*l).path,
            (*l).linenum,
        );
        (*ctx).complex_hostspec = 1 as libc::c_int;
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as size_t;
    while i < (*ctx).nkeys {
        if sshkey_equal((*l).key, *((*ctx).keys).offset(i as isize)) == 0 {
            i = i.wrapping_add(1);
            i;
        } else {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"hostkeys_find\0"))
                    .as_ptr(),
                1985 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"found %s key at %s:%ld\0" as *const u8 as *const libc::c_char,
                sshkey_ssh_name(*((*ctx).keys).offset(i as isize)),
                (*l).path,
                (*l).linenum,
            );
            let ref mut fresh0 = *((*ctx).keys_match).offset(i as isize);
            *fresh0 |= (*l).match_0;
            return 0 as libc::c_int;
        }
    }
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"hostkeys_find\0")).as_ptr(),
        1991 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"deprecated %s key at %s:%ld\0" as *const u8 as *const libc::c_char,
        sshkey_ssh_name((*l).key),
        (*l).path,
        (*l).linenum,
    );
    tmp = recallocarray(
        (*ctx).old_keys as *mut libc::c_void,
        (*ctx).nold,
        ((*ctx).nold).wrapping_add(1 as libc::c_int as libc::c_ulong),
        ::core::mem::size_of::<*mut sshkey>() as libc::c_ulong,
    ) as *mut *mut sshkey;
    if tmp.is_null() {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"hostkeys_find\0"))
                .as_ptr(),
            1994 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"recallocarray failed nold = %zu\0" as *const u8 as *const libc::c_char,
            (*ctx).nold,
        );
    }
    (*ctx).old_keys = tmp;
    let fresh1 = (*ctx).nold;
    (*ctx).nold = ((*ctx).nold).wrapping_add(1);
    let ref mut fresh2 = *((*ctx).old_keys).offset(fresh1 as isize);
    *fresh2 = (*l).key;
    (*l).key = 0 as *mut sshkey;
    return 0 as libc::c_int;
}
unsafe extern "C" fn hostkeys_check_old(
    mut l: *mut hostkey_foreach_line,
    mut _ctx: *mut libc::c_void,
) -> libc::c_int {
    let mut ctx: *mut hostkeys_update_ctx = _ctx as *mut hostkeys_update_ctx;
    let mut i: size_t = 0;
    let mut hashed: libc::c_int = 0;
    if (*l).status == 3 as libc::c_int as libc::c_uint || ((*l).key).is_null() {
        return 0 as libc::c_int;
    }
    hashed = ((*l).match_0
        & ((1 as libc::c_int) << 2 as libc::c_int | (1 as libc::c_int) << 3 as libc::c_int)
            as libc::c_uint) as libc::c_int;
    i = 0 as libc::c_int as size_t;
    while i < (*ctx).nold {
        if sshkey_equal((*l).key, *((*ctx).old_keys).offset(i as isize)) == 0 {
            i = i.wrapping_add(1);
            i;
        } else {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"hostkeys_check_old\0",
                ))
                .as_ptr(),
                2020 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"found deprecated %s key at %s:%ld as %s\0" as *const u8 as *const libc::c_char,
                sshkey_ssh_name(*((*ctx).old_keys).offset(i as isize)),
                (*l).path,
                (*l).linenum,
                if hashed != 0 {
                    b"[HASHED]\0" as *const u8 as *const libc::c_char
                } else {
                    (*l).hosts
                },
            );
            (*ctx).old_key_seen = 1 as libc::c_int;
            break;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn check_old_keys_othernames(mut ctx: *mut hostkeys_update_ctx) -> libc::c_int {
    let mut i: size_t = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"check_old_keys_othernames\0"))
            .as_ptr(),
        2038 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"checking for %zu deprecated keys\0" as *const u8 as *const libc::c_char,
        (*ctx).nold,
    );
    i = 0 as libc::c_int as size_t;
    while i < options.num_user_hostfiles as libc::c_ulong {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"check_old_keys_othernames\0",
            ))
            .as_ptr(),
            2042 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"searching %s for %s / %s\0" as *const u8 as *const libc::c_char,
            options.user_hostfiles[i as usize],
            (*ctx).host_str,
            if !((*ctx).ip_str).is_null() {
                (*ctx).ip_str as *const libc::c_char
            } else {
                b"(none)\0" as *const u8 as *const libc::c_char
            },
        );
        r = hostkeys_foreach(
            options.user_hostfiles[i as usize],
            Some(
                hostkeys_check_old
                    as unsafe extern "C" fn(
                        *mut hostkey_foreach_line,
                        *mut libc::c_void,
                    ) -> libc::c_int,
            ),
            ctx as *mut libc::c_void,
            (*ctx).host_str,
            (*ctx).ip_str,
            ((1 as libc::c_int) << 1 as libc::c_int) as u_int,
            0 as libc::c_int as u_int,
        );
        if r != 0 as libc::c_int {
            if r == -(24 as libc::c_int) && *libc::__errno_location() == 2 as libc::c_int {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"check_old_keys_othernames\0",
                    ))
                    .as_ptr(),
                    2048 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"hostkeys file %s does not exist\0" as *const u8 as *const libc::c_char,
                    options.user_hostfiles[i as usize],
                );
            } else {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"check_old_keys_othernames\0",
                    ))
                    .as_ptr(),
                    2052 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"hostkeys_foreach failed for %s\0" as *const u8 as *const libc::c_char,
                    options.user_hostfiles[i as usize],
                );
                return -(1 as libc::c_int);
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn hostkey_change_preamble(mut loglevel: LogLevel) {
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"hostkey_change_preamble\0"))
            .as_ptr(),
        2062 as libc::c_int,
        0 as libc::c_int,
        loglevel,
        0 as *const libc::c_char,
        b"The server has updated its host keys.\0" as *const u8 as *const libc::c_char,
    );
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"hostkey_change_preamble\0"))
            .as_ptr(),
        2064 as libc::c_int,
        0 as libc::c_int,
        loglevel,
        0 as *const libc::c_char,
        b"These changes were verified by the server's existing trusted key.\0" as *const u8
            as *const libc::c_char,
    );
}
unsafe extern "C" fn update_known_hosts(mut ctx: *mut hostkeys_update_ctx) {
    let mut r: libc::c_int = 0;
    let mut was_raw: libc::c_int = 0 as libc::c_int;
    let mut first: libc::c_int = 1 as libc::c_int;
    let mut asking: libc::c_int = (options.update_hostkeys == 2 as libc::c_int) as libc::c_int;
    let mut loglevel: LogLevel = (if asking != 0 {
        SYSLOG_LEVEL_INFO as libc::c_int
    } else {
        SYSLOG_LEVEL_VERBOSE as libc::c_int
    }) as LogLevel;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut response: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: size_t = 0;
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    i = 0 as libc::c_int as size_t;
    while i < (*ctx).nkeys {
        if !(*((*ctx).keys_verified).offset(i as isize) == 0) {
            fp = sshkey_fingerprint(
                *((*ctx).keys).offset(i as isize),
                options.fingerprint_hash,
                SSH_FP_DEFAULT,
            );
            if fp.is_null() {
                sshfatal(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"update_known_hosts\0",
                    ))
                    .as_ptr(),
                    2082 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
                );
            }
            if first != 0 && asking != 0 {
                hostkey_change_preamble(loglevel);
            }
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"update_known_hosts\0",
                ))
                .as_ptr(),
                2086 as libc::c_int,
                0 as libc::c_int,
                loglevel,
                0 as *const libc::c_char,
                b"Learned new hostkey: %s %s\0" as *const u8 as *const libc::c_char,
                sshkey_type(*((*ctx).keys).offset(i as isize)),
                fp,
            );
            first = 0 as libc::c_int;
            libc::free(fp as *mut libc::c_void);
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as size_t;
    while i < (*ctx).nold {
        fp = sshkey_fingerprint(
            *((*ctx).old_keys).offset(i as isize),
            options.fingerprint_hash,
            SSH_FP_DEFAULT,
        );
        if fp.is_null() {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"update_known_hosts\0",
                ))
                .as_ptr(),
                2093 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
            );
        }
        if first != 0 && asking != 0 {
            hostkey_change_preamble(loglevel);
        }
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"update_known_hosts\0"))
                .as_ptr(),
            2097 as libc::c_int,
            0 as libc::c_int,
            loglevel,
            0 as *const libc::c_char,
            b"Deprecating obsolete hostkey: %s %s\0" as *const u8 as *const libc::c_char,
            sshkey_type(*((*ctx).old_keys).offset(i as isize)),
            fp,
        );
        first = 0 as libc::c_int;
        libc::free(fp as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    if options.update_hostkeys == 2 as libc::c_int {
        if !(get_saved_tio()).is_null() {
            leave_raw_mode(1 as libc::c_int);
            was_raw = 1 as libc::c_int;
        }
        response = 0 as *mut libc::c_char;
        i = 0 as libc::c_int as size_t;
        while quit_pending == 0 && i < 3 as libc::c_int as libc::c_ulong {
            libc::free(response as *mut libc::c_void);
            response = read_passphrase(
                b"Accept updated hostkeys? (yes/no): \0" as *const u8 as *const libc::c_char,
                0x1 as libc::c_int,
            );
            if !response.is_null()
                && strcasecmp(response, b"yes\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
            {
                break;
            }
            if quit_pending != 0
                || response.is_null()
                || strcasecmp(response, b"no\0" as *const u8 as *const libc::c_char)
                    == 0 as libc::c_int
            {
                options.update_hostkeys = 0 as libc::c_int;
                break;
            } else {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"update_known_hosts\0",
                    ))
                    .as_ptr(),
                    2119 as libc::c_int,
                    0 as libc::c_int,
                    loglevel,
                    0 as *const libc::c_char,
                    b"Please enter \"yes\" or \"no\"\0" as *const u8 as *const libc::c_char,
                );
                i = i.wrapping_add(1);
                i;
            }
        }
        if quit_pending != 0 || i >= 3 as libc::c_int as libc::c_ulong || response.is_null() {
            options.update_hostkeys = 0 as libc::c_int;
        }
        libc::free(response as *mut libc::c_void);
        if was_raw != 0 {
            enter_raw_mode(1 as libc::c_int);
        }
    }
    if options.update_hostkeys == 0 as libc::c_int {
        return;
    }
    i = 0 as libc::c_int as size_t;
    while i < options.num_user_hostfiles as libc::c_ulong {
        if libc::stat(options.user_hostfiles[i as usize], &mut sb) != 0 as libc::c_int {
            if *libc::__errno_location() == 2 as libc::c_int {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"update_known_hosts\0",
                    ))
                    .as_ptr(),
                    2143 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"known hosts file %s does not exist\0" as *const u8 as *const libc::c_char,
                    options.user_hostfiles[i as usize],
                );
            } else {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"update_known_hosts\0",
                    ))
                    .as_ptr(),
                    2147 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"known hosts file %s inaccessible: %s\0" as *const u8 as *const libc::c_char,
                    options.user_hostfiles[i as usize],
                    libc::strerror(*libc::__errno_location()),
                );
            }
        } else {
            r = hostfile_replace_entries(
                options.user_hostfiles[i as usize],
                (*ctx).host_str,
                (*ctx).ip_str,
                if i == 0 as libc::c_int as libc::c_ulong {
                    (*ctx).keys
                } else {
                    0 as *mut *mut sshkey
                },
                if i == 0 as libc::c_int as libc::c_ulong {
                    (*ctx).nkeys
                } else {
                    0 as libc::c_int as libc::c_ulong
                },
                options.hash_known_hosts,
                0 as libc::c_int,
                options.fingerprint_hash,
            );
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"update_known_hosts\0",
                    ))
                    .as_ptr(),
                    2157 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"hostfile_replace_entries failed for %s\0" as *const u8 as *const libc::c_char,
                    options.user_hostfiles[i as usize],
                );
            }
        }
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn client_global_hostkeys_prove_confirm(
    mut ssh: *mut ssh,
    mut type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut _ctx: *mut libc::c_void,
) {
    let mut current_block: u64;
    let mut ctx: *mut hostkeys_update_ctx = _ctx as *mut hostkeys_update_ctx;
    let mut i: size_t = 0;
    let mut ndone: size_t = 0;
    let mut signdata: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut r: libc::c_int = 0;
    let mut plaintype: libc::c_int = 0;
    let mut sig: *const u_char = 0 as *const u_char;
    let mut rsa_kexalg: *const libc::c_char = 0 as *const libc::c_char;
    let mut alg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut siglen: size_t = 0;
    if (*ctx).nnew == 0 as libc::c_int as libc::c_ulong {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                b"client_global_hostkeys_prove_confirm\0",
            ))
            .as_ptr(),
            2176 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ctx->nnew == 0\0" as *const u8 as *const libc::c_char,
        );
    }
    if type_0 != 81 as libc::c_int {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                b"client_global_hostkeys_prove_confirm\0",
            ))
            .as_ptr(),
            2179 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Server failed to confirm ownership of private host keys\0" as *const u8
                as *const libc::c_char,
        );
        hostkeys_update_ctx_free(ctx);
        return;
    }
    if sshkey_type_plain(sshkey_type_from_name((*(*ssh).kex).hostkey_alg)) == KEY_RSA as libc::c_int
    {
        rsa_kexalg = (*(*ssh).kex).hostkey_alg;
    }
    signdata = crate::sshbuf::sshbuf_new();
    if signdata.is_null() {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                b"client_global_hostkeys_prove_confirm\0",
            ))
            .as_ptr(),
            2187 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"crate::crate::sshbuf::sshbuf::sshbuf_new failed\0" as *const u8
                as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int as size_t;
    ndone = i;
    loop {
        if !(i < (*ctx).nkeys) {
            current_block = 4488286894823169796;
            break;
        }
        if !(*((*ctx).keys_match).offset(i as isize) != 0) {
            plaintype = sshkey_type_plain((**((*ctx).keys).offset(i as isize)).type_0);
            sshbuf_reset(signdata);
            r = sshbuf_put_cstring(
                signdata,
                b"hostkeys-prove-00@openssh.com\0" as *const u8 as *const libc::c_char,
            );
            if r != 0 as libc::c_int
                || {
                    r = sshbuf_put_stringb(signdata, (*(*ssh).kex).session_id);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshkey_puts(*((*ctx).keys).offset(i as isize), signdata);
                    r != 0 as libc::c_int
                }
            {
                sshfatal(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                        b"client_global_hostkeys_prove_confirm\0",
                    ))
                    .as_ptr(),
                    2204 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"compose signdata\0" as *const u8 as *const libc::c_char,
                );
            }
            r = sshpkt_get_string_direct(ssh, &mut sig, &mut siglen);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                        b"client_global_hostkeys_prove_confirm\0",
                    ))
                    .as_ptr(),
                    2207 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"parse sig\0" as *const u8 as *const libc::c_char,
                );
                current_block = 15146261001000136824;
                break;
            } else {
                r = sshkey_get_sigtype(sig, siglen, &mut alg);
                if r != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                            b"client_global_hostkeys_prove_confirm\0",
                        ))
                        .as_ptr(),
                        2212 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        ssh_err(r),
                        b"server gave unintelligible signature for %s key %zu\0" as *const u8
                            as *const libc::c_char,
                        sshkey_type(*((*ctx).keys).offset(i as isize)),
                        i,
                    );
                    current_block = 15146261001000136824;
                    break;
                } else if plaintype == KEY_RSA as libc::c_int
                    && rsa_kexalg.is_null()
                    && match_pattern_list(
                        alg,
                        b"rsa-sha2-512,rsa-sha2-256\0" as *const u8 as *const libc::c_char,
                        0 as libc::c_int,
                    ) != 1 as libc::c_int
                {
                    crate::log::sshlog(
                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<
                            &[u8; 37],
                            &[libc::c_char; 37],
                        >(b"client_global_hostkeys_prove_confirm\0"))
                            .as_ptr(),
                        2223 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"server used untrusted RSA signature algorithm %s for key %zu, disregarding\0"
                            as *const u8 as *const libc::c_char,
                        alg,
                        i,
                    );
                    libc::free(alg as *mut libc::c_void);
                    sshkey_free(*((*ctx).keys).offset(i as isize));
                    let ref mut fresh3 = *((*ctx).keys).offset(i as isize);
                    *fresh3 = 0 as *mut sshkey;
                    ndone = ndone.wrapping_add(1);
                    ndone;
                } else {
                    crate::log::sshlog(
                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                            b"client_global_hostkeys_prove_confirm\0",
                        ))
                        .as_ptr(),
                        2232 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG3,
                        0 as *const libc::c_char,
                        b"verify %s key %zu using sigalg %s\0" as *const u8 as *const libc::c_char,
                        sshkey_type(*((*ctx).keys).offset(i as isize)),
                        i,
                        alg,
                    );
                    libc::free(alg as *mut libc::c_void);
                    r = sshkey_verify(
                        *((*ctx).keys).offset(i as isize),
                        sig,
                        siglen,
                        sshbuf_ptr(signdata),
                        sshbuf_len(signdata),
                        if plaintype == KEY_RSA as libc::c_int {
                            rsa_kexalg
                        } else {
                            0 as *const libc::c_char
                        },
                        0 as libc::c_int as u_int,
                        0 as *mut *mut sshkey_sig_details,
                    );
                    if r != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"clientloop.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                                b"client_global_hostkeys_prove_confirm\0",
                            ))
                            .as_ptr(),
                            2238 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            ssh_err(r),
                            b"server gave bad signature for %s key %zu\0" as *const u8
                                as *const libc::c_char,
                            sshkey_type(*((*ctx).keys).offset(i as isize)),
                            i,
                        );
                        current_block = 15146261001000136824;
                        break;
                    } else {
                        *((*ctx).keys_verified).offset(i as isize) = 1 as libc::c_int;
                        ndone = ndone.wrapping_add(1);
                        ndone;
                    }
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    match current_block {
        4488286894823169796 => {
            if ndone != (*ctx).nnew {
                sshfatal(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                        b"client_global_hostkeys_prove_confirm\0",
                    ))
                    .as_ptr(),
                    2247 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"ndone != ctx->nnew (%zu / %zu)\0" as *const u8 as *const libc::c_char,
                    ndone,
                    (*ctx).nnew,
                );
            }
            r = sshpkt_get_end(ssh);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 37], &[libc::c_char; 37]>(
                        b"client_global_hostkeys_prove_confirm\0",
                    ))
                    .as_ptr(),
                    2249 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"protocol error\0" as *const u8 as *const libc::c_char,
                );
            } else {
                update_known_hosts(ctx);
            }
        }
        _ => {}
    }
    hostkeys_update_ctx_free(ctx);
    hostkeys_update_complete = 1 as libc::c_int;
    client_repledge();
}
unsafe extern "C" fn key_accepted_by_hostkeyalgs(mut key: *const sshkey) -> libc::c_int {
    let mut ktype: *const libc::c_char = sshkey_ssh_name(key);
    let mut hostkeyalgs: *const libc::c_char = options.hostkeyalgorithms;
    if (*key).type_0 == KEY_UNSPEC as libc::c_int {
        return 0 as libc::c_int;
    }
    if (*key).type_0 == KEY_RSA as libc::c_int
        && (match_pattern_list(
            b"rsa-sha2-256\0" as *const u8 as *const libc::c_char,
            hostkeyalgs,
            0 as libc::c_int,
        ) == 1 as libc::c_int
            || match_pattern_list(
                b"rsa-sha2-512\0" as *const u8 as *const libc::c_char,
                hostkeyalgs,
                0 as libc::c_int,
            ) == 1 as libc::c_int)
    {
        return 1 as libc::c_int;
    }
    return (match_pattern_list(ktype, hostkeyalgs, 0 as libc::c_int) == 1 as libc::c_int)
        as libc::c_int;
}
unsafe extern "C" fn client_input_hostkeys(mut ssh: *mut ssh) -> libc::c_int {
    let mut current_block: u64;
    let mut blob: *const u_char = 0 as *const u_char;
    let mut i: size_t = 0;
    let mut len: size_t = 0 as libc::c_int as size_t;
    let mut buf: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut tmp: *mut *mut sshkey = 0 as *mut *mut sshkey;
    let mut r: libc::c_int = 0;
    let mut prove_sent: libc::c_int = 0 as libc::c_int;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    static mut hostkeys_seen: libc::c_int = 0 as libc::c_int;
    extern "C" {
        static mut hostaddr: sockaddr_storage;
    }
    let mut ctx: *mut hostkeys_update_ctx = 0 as *mut hostkeys_update_ctx;
    let mut want: u_int = 0;
    if hostkeys_seen != 0 {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"client_input_hostkeys\0"))
                .as_ptr(),
            2300 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"server already sent hostkeys\0" as *const u8 as *const libc::c_char,
        );
    }
    if can_update_hostkeys() == 0 {
        return 1 as libc::c_int;
    }
    hostkeys_seen = 1 as libc::c_int;
    ctx = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<hostkeys_update_ctx>() as libc::c_ulong,
    ) as *mut hostkeys_update_ctx;
    's_41: loop {
        if !(ssh_packet_remaining(ssh) > 0 as libc::c_int) {
            current_block = 14648156034262866959;
            break;
        }
        sshkey_free(key);
        key = 0 as *mut sshkey;
        r = sshpkt_get_string_direct(ssh, &mut blob, &mut len);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"client_input_hostkeys\0",
                ))
                .as_ptr(),
                2310 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"parse key\0" as *const u8 as *const libc::c_char,
            );
            current_block = 10705796018943961050;
            break;
        } else {
            r = sshkey_from_blob(blob, len, &mut key);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"client_input_hostkeys\0",
                    ))
                    .as_ptr(),
                    2316 as libc::c_int,
                    1 as libc::c_int,
                    (if r == -(14 as libc::c_int) {
                        SYSLOG_LEVEL_DEBUG1 as libc::c_int
                    } else {
                        SYSLOG_LEVEL_ERROR as libc::c_int
                    }) as LogLevel,
                    ssh_err(r),
                    b"convert key\0" as *const u8 as *const libc::c_char,
                );
            } else {
                fp = sshkey_fingerprint(key, options.fingerprint_hash, SSH_FP_DEFAULT);
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"client_input_hostkeys\0",
                    ))
                    .as_ptr(),
                    2321 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"received %s key %s\0" as *const u8 as *const libc::c_char,
                    sshkey_type(key),
                    fp,
                );
                libc::free(fp as *mut libc::c_void);
                if key_accepted_by_hostkeyalgs(key) == 0 {
                    crate::log::sshlog(
                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                            b"client_input_hostkeys\0",
                        ))
                        .as_ptr(),
                        2326 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG3,
                        0 as *const libc::c_char,
                        b"%s key not permitted by HostkeyAlgorithms\0" as *const u8
                            as *const libc::c_char,
                        sshkey_ssh_name(key),
                    );
                } else if sshkey_is_cert(key) != 0 {
                    crate::log::sshlog(
                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                            b"client_input_hostkeys\0",
                        ))
                        .as_ptr(),
                        2332 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG3,
                        0 as *const libc::c_char,
                        b"%s key is a certificate; skipping\0" as *const u8 as *const libc::c_char,
                        sshkey_ssh_name(key),
                    );
                } else {
                    i = 0 as libc::c_int as size_t;
                    while i < (*ctx).nkeys {
                        if sshkey_equal(key, *((*ctx).keys).offset(i as isize)) != 0 {
                            crate::log::sshlog(
                                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                    b"client_input_hostkeys\0",
                                ))
                                .as_ptr(),
                                2339 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"received duplicated %s host key\0" as *const u8
                                    as *const libc::c_char,
                                sshkey_ssh_name(key),
                            );
                            current_block = 10705796018943961050;
                            break 's_41;
                        } else {
                            i = i.wrapping_add(1);
                            i;
                        }
                    }
                    tmp = recallocarray(
                        (*ctx).keys as *mut libc::c_void,
                        (*ctx).nkeys,
                        ((*ctx).nkeys).wrapping_add(1 as libc::c_int as libc::c_ulong),
                        ::core::mem::size_of::<*mut sshkey>() as libc::c_ulong,
                    ) as *mut *mut sshkey;
                    if tmp.is_null() {
                        sshfatal(
                            b"clientloop.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                b"client_input_hostkeys\0",
                            ))
                            .as_ptr(),
                            2347 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"recallocarray failed nkeys = %zu\0" as *const u8
                                as *const libc::c_char,
                            (*ctx).nkeys,
                        );
                    }
                    (*ctx).keys = tmp;
                    let fresh4 = (*ctx).nkeys;
                    (*ctx).nkeys = ((*ctx).nkeys).wrapping_add(1);
                    let ref mut fresh5 = *((*ctx).keys).offset(fresh4 as isize);
                    *fresh5 = key;
                    key = 0 as *mut sshkey;
                }
            }
        }
    }
    match current_block {
        14648156034262866959 => {
            if (*ctx).nkeys == 0 as libc::c_int as libc::c_ulong {
                crate::log::sshlog(
                    b"clientloop.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"client_input_hostkeys\0",
                    ))
                    .as_ptr(),
                    2354 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"server sent no hostkeys\0" as *const u8 as *const libc::c_char,
                );
            } else {
                (*ctx).keys_match = calloc(
                    (*ctx).nkeys,
                    ::core::mem::size_of::<u_int>() as libc::c_ulong,
                ) as *mut u_int;
                if ((*ctx).keys_match).is_null() || {
                    (*ctx).keys_verified = calloc(
                        (*ctx).nkeys,
                        ::core::mem::size_of::<libc::c_int>() as libc::c_ulong,
                    ) as *mut libc::c_int;
                    ((*ctx).keys_verified).is_null()
                } {
                    sshfatal(
                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                            b"client_input_hostkeys\0",
                        ))
                        .as_ptr(),
                        2362 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"calloc failed\0" as *const u8 as *const libc::c_char,
                    );
                }
                get_hostfile_hostname_ipaddr(
                    host,
                    if options.check_host_ip != 0 {
                        &mut hostaddr as *mut sockaddr_storage as *mut sockaddr
                    } else {
                        0 as *mut sockaddr
                    },
                    options.port as u_short,
                    &mut (*ctx).host_str,
                    if options.check_host_ip != 0 {
                        &mut (*ctx).ip_str
                    } else {
                        0 as *mut *mut libc::c_char
                    },
                );
                i = 0 as libc::c_int as size_t;
                loop {
                    if !(i < options.num_user_hostfiles as libc::c_ulong) {
                        current_block = 980989089337379490;
                        break;
                    }
                    crate::log::sshlog(
                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                            b"client_input_hostkeys\0",
                        ))
                        .as_ptr(),
                        2373 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"searching %s for %s / %s\0" as *const u8 as *const libc::c_char,
                        options.user_hostfiles[i as usize],
                        (*ctx).host_str,
                        if !((*ctx).ip_str).is_null() {
                            (*ctx).ip_str as *const libc::c_char
                        } else {
                            b"(none)\0" as *const u8 as *const libc::c_char
                        },
                    );
                    r = hostkeys_foreach(
                        options.user_hostfiles[i as usize],
                        Some(
                            hostkeys_find
                                as unsafe extern "C" fn(
                                    *mut hostkey_foreach_line,
                                    *mut libc::c_void,
                                )
                                    -> libc::c_int,
                        ),
                        ctx as *mut libc::c_void,
                        (*ctx).host_str,
                        (*ctx).ip_str,
                        ((1 as libc::c_int) << 1 as libc::c_int) as u_int,
                        0 as libc::c_int as u_int,
                    );
                    if r != 0 as libc::c_int {
                        if r == -(24 as libc::c_int)
                            && *libc::__errno_location() == 2 as libc::c_int
                        {
                            crate::log::sshlog(
                                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                    b"client_input_hostkeys\0",
                                ))
                                .as_ptr(),
                                2379 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG1,
                                0 as *const libc::c_char,
                                b"hostkeys file %s does not exist\0" as *const u8
                                    as *const libc::c_char,
                                options.user_hostfiles[i as usize],
                            );
                        } else {
                            crate::log::sshlog(
                                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                    b"client_input_hostkeys\0",
                                ))
                                .as_ptr(),
                                2383 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                ssh_err(r),
                                b"hostkeys_foreach failed for %s\0" as *const u8
                                    as *const libc::c_char,
                                options.user_hostfiles[i as usize],
                            );
                            current_block = 10705796018943961050;
                            break;
                        }
                    }
                    i = i.wrapping_add(1);
                    i;
                }
                match current_block {
                    10705796018943961050 => {}
                    _ => {
                        (*ctx).nincomplete = 0 as libc::c_int as size_t;
                        (*ctx).nnew = (*ctx).nincomplete;
                        want = (1 as libc::c_int
                            | (if options.check_host_ip != 0 {
                                (1 as libc::c_int) << 1 as libc::c_int
                            } else {
                                0 as libc::c_int
                            })) as u_int;
                        i = 0 as libc::c_int as size_t;
                        while i < (*ctx).nkeys {
                            if *((*ctx).keys_match).offset(i as isize)
                                == 0 as libc::c_int as libc::c_uint
                            {
                                (*ctx).nnew = ((*ctx).nnew).wrapping_add(1);
                                (*ctx).nnew;
                            }
                            if *((*ctx).keys_match).offset(i as isize) & want != want {
                                (*ctx).nincomplete = ((*ctx).nincomplete).wrapping_add(1);
                                (*ctx).nincomplete;
                            }
                            i = i.wrapping_add(1);
                            i;
                        }
                        crate::log::sshlog(
                            b"clientloop.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<
                                &[u8; 22],
                                &[libc::c_char; 22],
                            >(b"client_input_hostkeys\0"))
                                .as_ptr(),
                            2401 as libc::c_int,
                            1 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG3,
                            0 as *const libc::c_char,
                            b"%zu server keys: %zu new, %zu retained, %zu incomplete match. %zu to remove\0"
                                as *const u8 as *const libc::c_char,
                            (*ctx).nkeys,
                            (*ctx).nnew,
                            ((*ctx).nkeys)
                                .wrapping_sub((*ctx).nnew)
                                .wrapping_sub((*ctx).nincomplete),
                            (*ctx).nincomplete,
                            (*ctx).nold,
                        );
                        if (*ctx).nnew == 0 as libc::c_int as libc::c_ulong
                            && (*ctx).nold == 0 as libc::c_int as libc::c_ulong
                        {
                            crate::log::sshlog(
                                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                    b"client_input_hostkeys\0",
                                ))
                                .as_ptr(),
                                2404 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG1,
                                0 as *const libc::c_char,
                                b"no new or deprecated keys from server\0" as *const u8
                                    as *const libc::c_char,
                            );
                        } else if (*ctx).complex_hostspec != 0 {
                            crate::log::sshlog(
                                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<
                                    &[u8; 22],
                                    &[libc::c_char; 22],
                                >(b"client_input_hostkeys\0"))
                                    .as_ptr(),
                                2411 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG1,
                                0 as *const libc::c_char,
                                b"CA/revocation marker, manual host list or wildcard host pattern found, skipping UserKnownHostsFile update\0"
                                    as *const u8 as *const libc::c_char,
                            );
                        } else if (*ctx).other_name_seen != 0 {
                            crate::log::sshlog(
                                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<
                                    &[u8; 22],
                                    &[libc::c_char; 22],
                                >(b"client_input_hostkeys\0"))
                                    .as_ptr(),
                                2416 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG1,
                                0 as *const libc::c_char,
                                b"host key found matching a different name/address, skipping UserKnownHostsFile update\0"
                                    as *const u8 as *const libc::c_char,
                            );
                        } else {
                            if (*ctx).nold != 0 as libc::c_int as libc::c_ulong {
                                if check_old_keys_othernames(ctx) != 0 as libc::c_int {
                                    current_block = 10705796018943961050;
                                } else if (*ctx).old_key_seen != 0 {
                                    crate::log::sshlog(
                                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<
                                            &[u8; 22],
                                            &[libc::c_char; 22],
                                        >(b"client_input_hostkeys\0"))
                                            .as_ptr(),
                                        2433 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG1,
                                        0 as *const libc::c_char,
                                        b"key(s) for %s%s%s exist under other names; skipping UserKnownHostsFile update\0"
                                            as *const u8 as *const libc::c_char,
                                        (*ctx).host_str,
                                        if ((*ctx).ip_str).is_null() {
                                            b"\0" as *const u8 as *const libc::c_char
                                        } else {
                                            b",\0" as *const u8 as *const libc::c_char
                                        },
                                        if ((*ctx).ip_str).is_null() {
                                            b"\0" as *const u8 as *const libc::c_char
                                        } else {
                                            (*ctx).ip_str as *const libc::c_char
                                        },
                                    );
                                    current_block = 10705796018943961050;
                                } else {
                                    current_block = 6528285054092551010;
                                }
                            } else {
                                current_block = 6528285054092551010;
                            }
                            match current_block {
                                10705796018943961050 => {}
                                _ => {
                                    if (*ctx).nnew == 0 as libc::c_int as libc::c_ulong {
                                        update_known_hosts(ctx);
                                    } else {
                                        crate::log::sshlog(
                                            b"clientloop.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 22],
                                                &[libc::c_char; 22],
                                            >(
                                                b"client_input_hostkeys\0"
                                            ))
                                            .as_ptr(),
                                            2451 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_DEBUG3,
                                            0 as *const libc::c_char,
                                            b"asking server to prove ownership for %zu keys\0"
                                                as *const u8
                                                as *const libc::c_char,
                                            (*ctx).nnew,
                                        );
                                        r = sshpkt_start(ssh, 80 as libc::c_int as u_char);
                                        if r != 0 as libc::c_int
                                            || {
                                                r = sshpkt_put_cstring(
                                                    ssh,
                                                    b"hostkeys-prove-00@openssh.com\0" as *const u8
                                                        as *const libc::c_char
                                                        as *const libc::c_void,
                                                );
                                                r != 0 as libc::c_int
                                            }
                                            || {
                                                r = sshpkt_put_u8(ssh, 1 as libc::c_int as u_char);
                                                r != 0 as libc::c_int
                                            }
                                        {
                                            sshfatal(
                                                b"clientloop.c\0" as *const u8
                                                    as *const libc::c_char,
                                                (*::core::mem::transmute::<
                                                    &[u8; 22],
                                                    &[libc::c_char; 22],
                                                >(
                                                    b"client_input_hostkeys\0"
                                                ))
                                                .as_ptr(),
                                                2456 as libc::c_int,
                                                1 as libc::c_int,
                                                SYSLOG_LEVEL_FATAL,
                                                ssh_err(r),
                                                b"prepare hostkeys-prove\0" as *const u8
                                                    as *const libc::c_char,
                                            );
                                        }
                                        buf = crate::sshbuf::sshbuf_new();
                                        if buf.is_null() {
                                            sshfatal(
                                                b"clientloop.c\0" as *const u8
                                                    as *const libc::c_char,
                                                (*::core::mem::transmute::<
                                                    &[u8; 22],
                                                    &[libc::c_char; 22],
                                                >(
                                                    b"client_input_hostkeys\0"
                                                ))
                                                .as_ptr(),
                                                2458 as libc::c_int,
                                                1 as libc::c_int,
                                                SYSLOG_LEVEL_FATAL,
                                                0 as *const libc::c_char,
                                                b"crate::crate::sshbuf::sshbuf::sshbuf_new\0"
                                                    as *const u8
                                                    as *const libc::c_char,
                                            );
                                        }
                                        i = 0 as libc::c_int as size_t;
                                        while i < (*ctx).nkeys {
                                            if !(*((*ctx).keys_match).offset(i as isize) != 0) {
                                                sshbuf_reset(buf);
                                                r = sshkey_putb(
                                                    *((*ctx).keys).offset(i as isize),
                                                    buf,
                                                );
                                                if r != 0 as libc::c_int || {
                                                    r = sshpkt_put_stringb(ssh, buf);
                                                    r != 0 as libc::c_int
                                                } {
                                                    sshfatal(
                                                        b"clientloop.c\0" as *const u8
                                                            as *const libc::c_char,
                                                        (*::core::mem::transmute::<
                                                            &[u8; 22],
                                                            &[libc::c_char; 22],
                                                        >(
                                                            b"client_input_hostkeys\0"
                                                        ))
                                                        .as_ptr(),
                                                        2465 as libc::c_int,
                                                        1 as libc::c_int,
                                                        SYSLOG_LEVEL_FATAL,
                                                        ssh_err(r),
                                                        b"assemble hostkeys-prove\0" as *const u8
                                                            as *const libc::c_char,
                                                    );
                                                }
                                            }
                                            i = i.wrapping_add(1);
                                            i;
                                        }
                                        r = sshpkt_send(ssh);
                                        if r != 0 as libc::c_int {
                                            sshfatal(
                                                b"clientloop.c\0" as *const u8
                                                    as *const libc::c_char,
                                                (*::core::mem::transmute::<
                                                    &[u8; 22],
                                                    &[libc::c_char; 22],
                                                >(
                                                    b"client_input_hostkeys\0"
                                                ))
                                                .as_ptr(),
                                                2468 as libc::c_int,
                                                1 as libc::c_int,
                                                SYSLOG_LEVEL_FATAL,
                                                ssh_err(r),
                                                b"send hostkeys-prove\0" as *const u8
                                                    as *const libc::c_char,
                                            );
                                        }
                                        client_register_global_confirm(
                                            Some(
                                                client_global_hostkeys_prove_confirm
                                                    as unsafe extern "C" fn(
                                                        *mut ssh,
                                                        libc::c_int,
                                                        u_int32_t,
                                                        *mut libc::c_void,
                                                    )
                                                        -> (),
                                            ),
                                            ctx as *mut libc::c_void,
                                        );
                                        ctx = 0 as *mut hostkeys_update_ctx;
                                        prove_sent = 1 as libc::c_int;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }
    hostkeys_update_ctx_free(ctx);
    sshkey_free(key);
    sshbuf_free(buf);
    if prove_sent == 0 {
        hostkeys_update_complete = 1 as libc::c_int;
        client_repledge();
    }
    return 1 as libc::c_int;
}
unsafe extern "C" fn client_input_global_request(
    mut _type_0: libc::c_int,
    mut _seq: u_int32_t,
    mut ssh: *mut ssh,
) -> libc::c_int {
    let mut current_block: u64;
    let mut rtype: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut want_reply: u_char = 0;
    let mut r: libc::c_int = 0;
    let mut success: libc::c_int = 0 as libc::c_int;
    r = sshpkt_get_cstring(ssh, &mut rtype, 0 as *mut size_t);
    if !(r != 0 as libc::c_int || {
        r = sshpkt_get_u8(ssh, &mut want_reply);
        r != 0 as libc::c_int
    }) {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
                b"client_input_global_request\0",
            ))
            .as_ptr(),
            2502 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"client_input_global_request: rtype %s want_reply %d\0" as *const u8
                as *const libc::c_char,
            rtype,
            want_reply as libc::c_int,
        );
        if libc::strcmp(
            rtype,
            b"hostkeys-00@openssh.com\0" as *const u8 as *const libc::c_char,
        ) == 0 as libc::c_int
        {
            success = client_input_hostkeys(ssh);
        }
        if want_reply != 0 {
            r = sshpkt_start(
                ssh,
                (if success != 0 {
                    81 as libc::c_int
                } else {
                    82 as libc::c_int
                }) as u_char,
            );
            if r != 0 as libc::c_int
                || {
                    r = sshpkt_send(ssh);
                    r != 0 as libc::c_int
                }
                || {
                    r = ssh_packet_write_wait(ssh);
                    r != 0 as libc::c_int
                }
            {
                current_block = 121348424899245253;
            } else {
                current_block = 2473556513754201174;
            }
        } else {
            current_block = 2473556513754201174;
        }
        match current_block {
            121348424899245253 => {}
            _ => {
                r = 0 as libc::c_int;
            }
        }
    }
    libc::free(rtype as *mut libc::c_void);
    return r;
}
unsafe extern "C" fn client_send_env(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut name: *const libc::c_char,
    mut val: *const libc::c_char,
) {
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"client_send_env\0")).as_ptr(),
        2523 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"channel %d: setting env %s = \"%s\"\0" as *const u8 as *const libc::c_char,
        id,
        name,
        val,
    );
    channel_request_start(
        ssh,
        id,
        b"env\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        0 as libc::c_int,
    );
    r = sshpkt_put_cstring(ssh, name as *const libc::c_void);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_cstring(ssh, val as *const libc::c_void);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"client_send_env\0"))
                .as_ptr(),
            2528 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send setenv\0" as *const u8 as *const libc::c_char,
        );
    }
}
pub unsafe extern "C" fn client_session2_setup(
    mut ssh: *mut ssh,
    mut id: libc::c_int,
    mut want_tty: libc::c_int,
    mut want_subsystem: libc::c_int,
    mut term: *const libc::c_char,
    mut tiop: *mut termios,
    mut in_fd: libc::c_int,
    mut cmd: *mut crate::sshbuf::sshbuf,
    mut env: *mut *mut libc::c_char,
) {
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut len: size_t = 0;
    let mut matched: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut name: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut val: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut c: *mut Channel = 0 as *mut Channel;
    crate::log::sshlog(
        b"clientloop.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"client_session2_setup\0"))
            .as_ptr(),
        2541 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"id %d\0" as *const u8 as *const libc::c_char,
        id,
    );
    c = channel_lookup(ssh, id);
    if c.is_null() {
        sshfatal(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"client_session2_setup\0"))
                .as_ptr(),
            2544 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"channel %d: unknown channel\0" as *const u8 as *const libc::c_char,
            id,
        );
    }
    ssh_packet_set_interactive(
        ssh,
        want_tty,
        options.ip_qos_interactive,
        options.ip_qos_bulk,
    );
    if want_tty != 0 {
        let mut ws: winsize = winsize {
            ws_row: 0,
            ws_col: 0,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        if ioctl(
            in_fd,
            0x5413 as libc::c_int as libc::c_ulong,
            &mut ws as *mut winsize,
        ) == -(1 as libc::c_int)
        {
            memset(
                &mut ws as *mut winsize as *mut libc::c_void,
                0 as libc::c_int,
                ::core::mem::size_of::<winsize>() as libc::c_ulong,
            );
        }
        channel_request_start(
            ssh,
            id,
            b"pty-req\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            1 as libc::c_int,
        );
        client_expect_confirm(
            ssh,
            id,
            b"PTY allocation\0" as *const u8 as *const libc::c_char,
            CONFIRM_TTY,
        );
        r = sshpkt_put_cstring(
            ssh,
            (if !term.is_null() {
                term
            } else {
                b"\0" as *const u8 as *const libc::c_char
            }) as *const libc::c_void,
        );
        if r != 0 as libc::c_int
            || {
                r = sshpkt_put_u32(ssh, ws.ws_col as u_int);
                r != 0 as libc::c_int
            }
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
        {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"client_session2_setup\0",
                ))
                .as_ptr(),
                2564 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"build pty-req\0" as *const u8 as *const libc::c_char,
            );
        }
        if tiop.is_null() {
            tiop = get_saved_tio();
        }
        ssh_tty_make_modes(ssh, -(1 as libc::c_int), tiop);
        r = sshpkt_send(ssh);
        if r != 0 as libc::c_int {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"client_session2_setup\0",
                ))
                .as_ptr(),
                2569 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"send pty-req\0" as *const u8 as *const libc::c_char,
            );
        }
        (*c).client_tty = 1 as libc::c_int;
    }
    if options.num_send_env != 0 as libc::c_int as libc::c_uint && !env.is_null() {
        crate::log::sshlog(
            b"clientloop.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"client_session2_setup\0"))
                .as_ptr(),
            2576 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Sending environment.\0" as *const u8 as *const libc::c_char,
        );
        i = 0 as libc::c_int as size_t;
        while !(*env.offset(i as isize)).is_null() {
            name = crate::xmalloc::xstrdup(*env.offset(i as isize));
            val = libc::strchr(name, '=' as i32);
            if val.is_null() {
                libc::free(name as *mut libc::c_void);
            } else {
                let fresh6 = val;
                val = val.offset(1);
                *fresh6 = '\0' as i32 as libc::c_char;
                matched = 0 as libc::c_int;
                j = 0 as libc::c_int as size_t;
                while j < options.num_send_env as libc::c_ulong {
                    if match_pattern(name, *(options.send_env).offset(j as isize)) != 0 {
                        matched = 1 as libc::c_int;
                        break;
                    } else {
                        j = j.wrapping_add(1);
                        j;
                    }
                }
                if matched == 0 {
                    crate::log::sshlog(
                        b"clientloop.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                            b"client_session2_setup\0",
                        ))
                        .as_ptr(),
                        2594 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG3,
                        0 as *const libc::c_char,
                        b"Ignored env %s\0" as *const u8 as *const libc::c_char,
                        name,
                    );
                    libc::free(name as *mut libc::c_void);
                } else {
                    client_send_env(ssh, id, name, val);
                    libc::free(name as *mut libc::c_void);
                }
            }
            i = i.wrapping_add(1);
            i;
        }
    }
    i = 0 as libc::c_int as size_t;
    while i < options.num_setenv as libc::c_ulong {
        name = crate::xmalloc::xstrdup(*(options.setenv).offset(i as isize));
        val = libc::strchr(name, '=' as i32);
        if val.is_null() {
            libc::free(name as *mut libc::c_void);
        } else {
            let fresh7 = val;
            val = val.offset(1);
            *fresh7 = '\0' as i32 as libc::c_char;
            client_send_env(ssh, id, name, val);
            libc::free(name as *mut libc::c_void);
        }
        i = i.wrapping_add(1);
        i;
    }
    len = sshbuf_len(cmd);
    if len > 0 as libc::c_int as libc::c_ulong {
        if len > 900 as libc::c_int as libc::c_ulong {
            len = 900 as libc::c_int as size_t;
        }
        if want_subsystem != 0 {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"client_session2_setup\0",
                ))
                .as_ptr(),
                2620 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Sending subsystem: %.*s\0" as *const u8 as *const libc::c_char,
                len as libc::c_int,
                sshbuf_ptr(cmd),
            );
            channel_request_start(
                ssh,
                id,
                b"subsystem\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                1 as libc::c_int,
            );
            client_expect_confirm(
                ssh,
                id,
                b"subsystem\0" as *const u8 as *const libc::c_char,
                CONFIRM_CLOSE,
            );
        } else {
            crate::log::sshlog(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"client_session2_setup\0",
                ))
                .as_ptr(),
                2626 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Sending command: %.*s\0" as *const u8 as *const libc::c_char,
                len as libc::c_int,
                sshbuf_ptr(cmd),
            );
            channel_request_start(
                ssh,
                id,
                b"exec\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
                1 as libc::c_int,
            );
            client_expect_confirm(
                ssh,
                id,
                b"exec\0" as *const u8 as *const libc::c_char,
                CONFIRM_CLOSE,
            );
        }
        r = sshpkt_put_stringb(ssh, cmd);
        if r != 0 as libc::c_int || {
            r = sshpkt_send(ssh);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"client_session2_setup\0",
                ))
                .as_ptr(),
                2632 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"send command\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        channel_request_start(
            ssh,
            id,
            b"shell\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            1 as libc::c_int,
        );
        client_expect_confirm(
            ssh,
            id,
            b"shell\0" as *const u8 as *const libc::c_char,
            CONFIRM_CLOSE,
        );
        r = sshpkt_send(ssh);
        if r != 0 as libc::c_int {
            sshfatal(
                b"clientloop.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"client_session2_setup\0",
                ))
                .as_ptr(),
                2637 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"send shell\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    session_setup_complete = 1 as libc::c_int;
    client_repledge();
}
unsafe extern "C" fn client_init_dispatch(mut ssh: *mut ssh) {
    ssh_dispatch_init(
        ssh,
        Some(
            dispatch_protocol_error
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        97 as libc::c_int,
        Some(
            channel_input_oclose
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        94 as libc::c_int,
        Some(
            channel_input_data
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        96 as libc::c_int,
        Some(
            channel_input_ieof
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        95 as libc::c_int,
        Some(
            channel_input_extended_data
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        90 as libc::c_int,
        Some(
            client_input_channel_open
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        91 as libc::c_int,
        Some(
            channel_input_open_confirmation
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        92 as libc::c_int,
        Some(
            channel_input_open_failure
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        98 as libc::c_int,
        Some(
            client_input_channel_req
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        93 as libc::c_int,
        Some(
            channel_input_window_adjust
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        99 as libc::c_int,
        Some(
            channel_input_status_confirm
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        100 as libc::c_int,
        Some(
            channel_input_status_confirm
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        80 as libc::c_int,
        Some(
            client_input_global_request
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        20 as libc::c_int,
        Some(
            kex_input_kexinit
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        82 as libc::c_int,
        Some(
            client_global_request_reply
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
    ssh_dispatch_set(
        ssh,
        81 as libc::c_int,
        Some(
            client_global_request_reply
                as unsafe extern "C" fn(libc::c_int, u_int32_t, *mut ssh) -> libc::c_int,
        ),
    );
}
pub unsafe extern "C" fn client_stop_mux() {
    if !(options.control_path).is_null() && muxserver_sock != -(1 as libc::c_int) {
        unlink(options.control_path);
    }
    if options.control_persist != 0 || options.session_type == 0 as libc::c_int {
        session_closed = 1 as libc::c_int;
        setproctitle(b"[stopped mux]\0" as *const u8 as *const libc::c_char);
    }
}
pub unsafe extern "C" fn cleanup_exit(mut i: libc::c_int) -> ! {
    leave_raw_mode((options.request_tty == 3 as libc::c_int) as libc::c_int);
    if !(options.control_path).is_null() && muxserver_sock != -(1 as libc::c_int) {
        unlink(options.control_path);
    }
    ssh_kill_proxy_command();
    libc::_exit(i);
}
unsafe extern "C" fn run_static_initializers() {
    global_confirms = {
        let mut init = global_confirms {
            tqh_first: 0 as *mut global_confirm,
            tqh_last: &mut global_confirms.tqh_first,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
