use crate::atomicio::atomicio;
use crate::log::log_init;
use ::libc;
use libc::close;
use libc::kill;

extern "C" {
    pub type sockaddr_x25;
    pub type sockaddr_un;
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
    pub type ssh_channels;
    pub type sshbuf;
    pub type ec_key_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_group_st;
    pub type dh_st;
    pub type umac_ctx;
    pub type ssh_hmac_ctx;
    pub type sshcipher;
    pub type session_state;
    pub type ssh_digest_ctx;
    pub type ssh_sandbox;
    static mut stderr: *mut libc::FILE;
    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::FILE;

    fn socket(__domain: libc::c_int, __type: libc::c_int, __protocol: libc::c_int) -> libc::c_int;

    fn bind(__fd: libc::c_int, __addr: __CONST_SOCKADDR_ARG, __len: socklen_t) -> libc::c_int;
    fn getpeername(__fd: libc::c_int, __addr: __SOCKADDR_ARG, __len: *mut socklen_t)
        -> libc::c_int;
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
    fn listen(__fd: libc::c_int, __n: libc::c_int) -> libc::c_int;
    fn accept(__fd: libc::c_int, __addr: __SOCKADDR_ARG, __addr_len: *mut socklen_t)
        -> libc::c_int;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn endpwent();
    fn getpwnam(__name: *const libc::c_char) -> *mut libc::passwd;
    fn platform_pre_listen();
    fn platform_pre_fork();
    fn platform_pre_restart();
    fn platform_post_fork_parent(child_pid: pid_t);
    fn platform_post_fork_child();

    fn sigemptyset(__set: *mut sigset_t) -> libc::c_int;
    fn sigaddset(__set: *mut sigset_t, __signo: libc::c_int) -> libc::c_int;
    fn sigprocmask(
        __how: libc::c_int,
        __set: *const sigset_t,
        __oset: *mut sigset_t,
    ) -> libc::c_int;

    fn closefrom(__lowfd: libc::c_int);
    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;
    fn pipe(__pipedes: *mut libc::c_int) -> libc::c_int;
    fn alarm(__seconds: libc::c_uint) -> libc::c_uint;
    fn usleep(__useconds: __useconds_t) -> libc::c_int;
    fn chdir(__path: *const libc::c_char) -> libc::c_int;
    fn dup(__fd: libc::c_int) -> libc::c_int;

    fn execv(__path: *const libc::c_char, __argv: *const *mut libc::c_char) -> libc::c_int;

    fn getpgid(__pid: __pid_t) -> __pid_t;
    fn setsid() -> __pid_t;

    fn geteuid() -> __uid_t;

    fn unlink(__name: *const libc::c_char) -> libc::c_int;
    static mut BSDoptarg: *mut libc::c_char;
    static mut BSDoptind: libc::c_int;

    fn daemon(__nochdir: libc::c_int, __noclose: libc::c_int) -> libc::c_int;
    fn chroot(__path: *const libc::c_char) -> libc::c_int;
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
    fn setproctitle(fmt: *const libc::c_char, _: ...);
    fn compat_init_setproctitle(argc: libc::c_int, argv: *mut *mut libc::c_char);

    fn ppoll(
        __fds: *mut pollfd,
        __nfds: nfds_t,
        __timeout: *const libc::timespec,
        __ss: *const __sigset_t,
    ) -> libc::c_int;
    fn arc4random_buf(_: *mut libc::c_void, _: size_t);
    fn arc4random_uniform(_: uint32_t) -> uint32_t;

    fn freezero(_: *mut libc::c_void, _: size_t);
    fn seed_rng();

    fn fcntl(__fd: libc::c_int, __cmd: libc::c_int, _: ...) -> libc::c_int;
    fn setgroups(__n: size_t, __groups: *const __gid_t) -> libc::c_int;

    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn setenv(
        __name: *const libc::c_char,
        __value: *const libc::c_char,
        __replace: libc::c_int,
    ) -> libc::c_int;
    fn unsetenv(__name: *const libc::c_char) -> libc::c_int;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn OpenSSL_version(type_0: libc::c_int) -> *const libc::c_char;
    fn RAND_bytes(buf: *mut libc::c_uchar, num: libc::c_int) -> libc::c_int;
    fn RAND_seed(buf: *const libc::c_void, num: libc::c_int);
    fn RAND_poll() -> libc::c_int;
    fn xmalloc(_: size_t) -> *mut libc::c_void;
    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn disconnect_controlling_tty();
    fn ssh_packet_set_connection(_: *mut ssh, _: libc::c_int, _: libc::c_int) -> *mut ssh;
    fn ssh_packet_set_timeout(_: *mut ssh, _: libc::c_int, _: libc::c_int);
    fn ssh_packet_set_nonblocking(_: *mut ssh);
    fn ssh_packet_get_connection_in(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_close(_: *mut ssh);
    fn ssh_packet_clear_keys(_: *mut ssh);
    fn ssh_packet_set_server(_: *mut ssh);
    fn ssh_packet_set_authenticated(_: *mut ssh);
    fn ssh_packet_get_bytes(_: *mut ssh, _: *mut u_int64_t, _: *mut u_int64_t);
    fn ssh_packet_connection_is_on_socket(_: *mut ssh) -> libc::c_int;
    fn ssh_remote_ipaddr(_: *mut ssh) -> *const libc::c_char;
    fn ssh_remote_port(_: *mut ssh) -> libc::c_int;
    fn ssh_local_port(_: *mut ssh) -> libc::c_int;
    fn ssh_packet_rdomain_in(_: *mut ssh) -> *const libc::c_char;
    fn ssh_packet_set_rekey_limits(_: *mut ssh, _: u_int64_t, _: u_int32_t);
    fn sshpkt_start(ssh: *mut ssh, type_0: u_char) -> libc::c_int;
    fn sshpkt_send(ssh: *mut ssh) -> libc::c_int;
    fn sshpkt_fatal(ssh: *mut ssh, r: libc::c_int, fmt: *const libc::c_char, _: ...) -> !;
    fn sshpkt_put_u8(ssh: *mut ssh, val: u_char) -> libc::c_int;
    fn sshpkt_put_cstring(ssh: *mut ssh, v: *const libc::c_void) -> libc::c_int;
    fn sshpkt_put_stringb(ssh: *mut ssh, v: *const sshbuf) -> libc::c_int;
    fn ssh_dispatch_run_fatal(_: *mut ssh, _: libc::c_int, _: *mut sig_atomic_t);

    fn log_verbose_add(_: *const libc::c_char);
    fn set_log_handler(_: Option<log_handler_fn>, _: *mut libc::c_void);

    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn log_redirect_stderr_to(_: *const libc::c_char);
    fn sshsigdie(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
        _: LogLevel,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: ...
    ) -> !;
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
    fn sshbuf_new() -> *mut sshbuf;
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_reset(buf: *mut sshbuf);
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_ptr(buf: *const sshbuf) -> *const u_char;
    fn sshbuf_put(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_putf(buf: *mut sshbuf, fmt: *const libc::c_char, _: ...) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_get_string(
        buf: *mut sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_stringb(buf: *mut sshbuf, v: *mut sshbuf) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_stringb(buf: *mut sshbuf, v: *const sshbuf) -> libc::c_int;
    fn sshbuf_dup_string(buf: *mut sshbuf) -> *mut libc::c_char;
    fn daemonized() -> libc::c_int;

    fn set_reuseaddr(_: libc::c_int) -> libc::c_int;
    fn set_rdomain(_: libc::c_int, _: *const libc::c_char) -> libc::c_int;

    fn convtime(_: *const libc::c_char) -> libc::c_int;
    fn fmt_timeframe(t: time_t) -> *const libc::c_char;
    fn xextendf(
        s: *mut *mut libc::c_char,
        sep: *const libc::c_char,
        fmt: *const libc::c_char,
        _: ...
    );

    fn monotime() -> time_t;
    fn path_absolute(_: *const libc::c_char) -> libc::c_int;
    fn stdfd_devnull(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn sock_set_v6only(_: libc::c_int);
    fn pwcopy(_: *mut libc::passwd) -> *mut libc::passwd;
    fn ssh_gai_strerror(_: libc::c_int) -> *const libc::c_char;
    
    fn match_pattern_list(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn get_connection_info(_: *mut ssh, _: libc::c_int, _: libc::c_int) -> *mut connection_info;
    fn initialize_server_options(_: *mut ServerOptions);
    fn fill_default_server_options(_: *mut ServerOptions);
    fn process_server_config_line(
        _: *mut ServerOptions,
        _: *mut libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: *mut libc::c_int,
        _: *mut connection_info,
        includes_0: *mut include_list,
    ) -> libc::c_int;
    fn process_permitopen(ssh: *mut ssh, options_0: *mut ServerOptions);
    fn process_channel_timeouts(ssh: *mut ssh, _: *mut ServerOptions);
    fn load_server_config(_: *const libc::c_char, _: *mut sshbuf);
    fn parse_server_config(
        _: *mut ServerOptions,
        _: *const libc::c_char,
        _: *mut sshbuf,
        includes_0: *mut include_list,
        _: *mut connection_info,
        _: libc::c_int,
    );
    fn parse_server_match_config(
        _: *mut ServerOptions,
        includes_0: *mut include_list,
        _: *mut connection_info,
    );
    fn parse_server_match_testspec(_: *mut connection_info, _: *mut libc::c_char) -> libc::c_int;
    fn dump_config(_: *mut ServerOptions);
    fn servconf_add_hostkey(
        _: *const libc::c_char,
        _: libc::c_int,
        _: *mut ServerOptions,
        path: *const libc::c_char,
        _: libc::c_int,
    );
    fn servconf_add_hostcert(
        _: *const libc::c_char,
        _: libc::c_int,
        _: *mut ServerOptions,
        path: *const libc::c_char,
    );
    fn permanently_set_uid(_: *mut libc::passwd);
    fn ssh_digest_bytes(alg: libc::c_int) -> size_t;
    fn ssh_digest_start(alg: libc::c_int) -> *mut ssh_digest_ctx;
    fn ssh_digest_update(
        ctx: *mut ssh_digest_ctx,
        m: *const libc::c_void,
        mlen: size_t,
    ) -> libc::c_int;
    fn ssh_digest_final(ctx: *mut ssh_digest_ctx, d: *mut u_char, dlen: size_t) -> libc::c_int;
    fn ssh_digest_free(ctx: *mut ssh_digest_ctx);
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_equal_public(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_equal(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_fingerprint(_: *const sshkey, _: libc::c_int, _: sshkey_fp_rep) -> *mut libc::c_char;
    fn sshkey_type(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_from_private(_: *const sshkey, _: *mut *mut sshkey) -> libc::c_int;
    fn sshkey_shield_private(_: *mut sshkey) -> libc::c_int;
    fn sshkey_is_cert(_: *const sshkey) -> libc::c_int;
    fn sshkey_is_sk(_: *const sshkey) -> libc::c_int;
    fn sshkey_ssh_name(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_putb(_: *const sshkey, _: *mut sshbuf) -> libc::c_int;
    fn sshkey_sign(
        _: *mut sshkey,
        _: *mut *mut u_char,
        _: *mut size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: u_int,
    ) -> libc::c_int;
    fn sshkey_private_serialize(key: *mut sshkey, buf: *mut sshbuf) -> libc::c_int;
    fn sshkey_check_rsa_length(_: *const sshkey, _: libc::c_int) -> libc::c_int;
    fn kex_proposal_populate_entries(
        _: *mut ssh,
        prop: *mut *mut libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
    );
    fn kex_proposal_free_entries(prop: *mut *mut libc::c_char);
    fn kex_exchange_identification(
        _: *mut ssh,
        _: libc::c_int,
        _: *const libc::c_char,
    ) -> libc::c_int;
    fn kex_setup(_: *mut ssh, _: *mut *mut libc::c_char) -> libc::c_int;
    fn kexgex_server(_: *mut ssh) -> libc::c_int;
    fn kex_gen_server(_: *mut ssh) -> libc::c_int;
    fn sshkey_load_public(
        _: *const libc::c_char,
        _: *mut *mut sshkey,
        _: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sshkey_load_private(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut *mut sshkey,
        _: *mut *mut libc::c_char,
    ) -> libc::c_int;

    fn get_peer_ipaddr(_: libc::c_int) -> *mut libc::c_char;
    fn get_peer_port(_: libc::c_int) -> libc::c_int;
    fn get_local_ipaddr(_: libc::c_int) -> *mut libc::c_char;
    fn get_local_port(_: libc::c_int) -> libc::c_int;
    fn do_authentication2(_: *mut ssh);
    fn auth2_methods_valid(_: *const libc::c_char, _: libc::c_int) -> libc::c_int;
    fn privsep_challenge_enable();
    fn auth_debug_reset();
    fn ssh_get_authentication_socket(fdp: *mut libc::c_int) -> libc::c_int;
    fn ssh_agent_sign(
        sock: libc::c_int,
        key: *const sshkey,
        sigp: *mut *mut u_char,
        lenp: *mut size_t,
        data: *const u_char,
        datalen: size_t,
        alg: *const libc::c_char,
        compat: u_int,
    ) -> libc::c_int;
    fn ssh_msg_send(_: libc::c_int, _: u_char, _: *mut sshbuf) -> libc::c_int;
    fn ssh_msg_recv(_: libc::c_int, _: *mut sshbuf) -> libc::c_int;
    fn channel_init_channels(ssh: *mut ssh);
    fn channel_set_af(_: *mut ssh, af: libc::c_int);
    fn do_authenticated(_: *mut ssh, _: *mut Authctxt);
    fn do_cleanup(_: *mut ssh, _: *mut Authctxt);
    fn do_setusercontext(_: *mut libc::passwd);
    fn monitor_init() -> *mut monitor;
    fn monitor_reinit(_: *mut monitor);
    fn monitor_child_preauth(_: *mut ssh, _: *mut monitor);
    fn monitor_child_postauth(_: *mut ssh, _: *mut monitor);
    fn monitor_clear_keystate(_: *mut ssh, _: *mut monitor);
    fn monitor_apply_keystate(_: *mut ssh, _: *mut monitor);
    fn mm_log_handler(_: LogLevel, _: libc::c_int, _: *const libc::c_char, _: *mut libc::c_void);
    fn mm_sshkey_sign(
        _: *mut ssh,
        _: *mut sshkey,
        _: *mut *mut u_char,
        _: *mut size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const libc::c_char,
        compat: u_int,
    ) -> libc::c_int;
    fn mm_terminate();
    fn mm_send_keystate(_: *mut ssh, _: *mut monitor);
    fn ssh_sandbox_init(_: *mut monitor) -> *mut ssh_sandbox;
    fn ssh_sandbox_child(_: *mut ssh_sandbox);
    fn ssh_sandbox_parent_finish(_: *mut ssh_sandbox);
    fn ssh_sandbox_parent_preauth(_: *mut ssh_sandbox, _: pid_t);
    fn sshauthopt_new_with_keys_defaults() -> *mut sshauthopt;
    fn srclimit_init(_: libc::c_int, _: libc::c_int, _: libc::c_int, _: libc::c_int);
    fn srclimit_check_allow(_: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn srclimit_done(_: libc::c_int);
    fn dh_set_moduli_file(_: *const libc::c_char);
    static mut __progname: *mut libc::c_char;
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
pub type __useconds_t = libc::c_uint;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type gid_t = __gid_t;
pub type mode_t = __mode_t;
pub type pid_t = __pid_t;
pub type ssize_t = __ssize_t;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __sigset_t {
    pub __val: [libc::c_ulong; 16],
}
pub type sigset_t = __sigset_t;

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
pub type uint64_t = __uint64_t;

pub type C2RustUnnamed_0 = libc::c_uint;
pub const IPPROTO_MAX: C2RustUnnamed_0 = 263;
pub const IPPROTO_MPTCP: C2RustUnnamed_0 = 262;
pub const IPPROTO_RAW: C2RustUnnamed_0 = 255;
pub const IPPROTO_ETHERNET: C2RustUnnamed_0 = 143;
pub const IPPROTO_MPLS: C2RustUnnamed_0 = 137;
pub const IPPROTO_UDPLITE: C2RustUnnamed_0 = 136;
pub const IPPROTO_SCTP: C2RustUnnamed_0 = 132;
pub const IPPROTO_COMP: C2RustUnnamed_0 = 108;
pub const IPPROTO_PIM: C2RustUnnamed_0 = 103;
pub const IPPROTO_ENCAP: C2RustUnnamed_0 = 98;
pub const IPPROTO_BEETPH: C2RustUnnamed_0 = 94;
pub const IPPROTO_MTP: C2RustUnnamed_0 = 92;
pub const IPPROTO_AH: C2RustUnnamed_0 = 51;
pub const IPPROTO_ESP: C2RustUnnamed_0 = 50;
pub const IPPROTO_GRE: C2RustUnnamed_0 = 47;
pub const IPPROTO_RSVP: C2RustUnnamed_0 = 46;
pub const IPPROTO_IPV6: C2RustUnnamed_0 = 41;
pub const IPPROTO_DCCP: C2RustUnnamed_0 = 33;
pub const IPPROTO_TP: C2RustUnnamed_0 = 29;
pub const IPPROTO_IDP: C2RustUnnamed_0 = 22;
pub const IPPROTO_UDP: C2RustUnnamed_0 = 17;
pub const IPPROTO_PUP: C2RustUnnamed_0 = 12;
pub const IPPROTO_EGP: C2RustUnnamed_0 = 8;
pub const IPPROTO_TCP: C2RustUnnamed_0 = 6;
pub const IPPROTO_IPIP: C2RustUnnamed_0 = 4;
pub const IPPROTO_IGMP: C2RustUnnamed_0 = 2;
pub const IPPROTO_ICMP: C2RustUnnamed_0 = 1;
pub const IPPROTO_IP: C2RustUnnamed_0 = 0;

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
    pub private_keys: C2RustUnnamed_3,
    pub public_keys: C2RustUnnamed_1,
    pub authctxt: *mut libc::c_void,
    pub chanctxt: *mut ssh_channels,
    pub app_data: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub tqh_first: *mut key_entry,
    pub tqh_last: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct key_entry {
    pub next: C2RustUnnamed_2,
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
pub struct C2RustUnnamed_2 {
    pub tqe_next: *mut key_entry,
    pub tqe_prev: *mut *mut key_entry,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_3 {
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
    pub my: *mut sshbuf,
    pub peer: *mut sshbuf,
    pub client_version: *mut sshbuf,
    pub server_version: *mut sshbuf,
    pub session_id: *mut sshbuf,
    pub initial_sig: *mut sshbuf,
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
    pub client_pub: *mut sshbuf,
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
pub type C2RustUnnamed_4 = libc::c_uint;
pub const DISPATCH_NONBLOCK: C2RustUnnamed_4 = 1;
pub const DISPATCH_BLOCK: C2RustUnnamed_4 = 0;
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
pub type log_handler_fn =
    unsafe extern "C" fn(LogLevel, libc::c_int, *const libc::c_char, *mut libc::c_void) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct monitor {
    pub m_recvfd: libc::c_int,
    pub m_sendfd: libc::c_int,
    pub m_log_recvfd: libc::c_int,
    pub m_log_sendfd: libc::c_int,
    pub m_pkex: *mut *mut kex,
    pub m_pid: pid_t,
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
    pub loginmsg: *mut sshbuf,
    pub prev_keys: *mut *mut sshkey,
    pub nprev_keys: u_int,
    pub auth_method_key: *mut sshkey,
    pub auth_method_info: *mut libc::c_char,
    pub session_info: *mut sshbuf,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ForwardOptions {
    pub gateway_ports: libc::c_int,
    pub streamlocal_bind_mask: mode_t,
    pub streamlocal_bind_unlink: libc::c_int,
}
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
pub struct connection_info {
    pub user: *const libc::c_char,
    pub host: *const libc::c_char,
    pub address: *const libc::c_char,
    pub laddress: *const libc::c_char,
    pub lport: libc::c_int,
    pub rdomain: *const libc::c_char,
    pub test: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct include_item {
    pub selector: *mut libc::c_char,
    pub filename: *mut libc::c_char,
    pub contents: *mut sshbuf,
    pub entry: C2RustUnnamed_5,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_5 {
    pub tqe_next: *mut include_item,
    pub tqe_prev: *mut *mut include_item,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct include_list {
    pub tqh_first: *mut include_item,
    pub tqh_last: *mut *mut include_item,
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
pub type kex_exchange = libc::c_uint;
pub const KEX_MAX: kex_exchange = 10;
pub const KEX_KEM_SNTRUP761X25519_SHA512: kex_exchange = 9;
pub const KEX_C25519_SHA256: kex_exchange = 8;
pub const KEX_ECDH_SHA2: kex_exchange = 7;
pub const KEX_DH_GEX_SHA256: kex_exchange = 6;
pub const KEX_DH_GEX_SHA1: kex_exchange = 5;
pub const KEX_DH_GRP18_SHA512: kex_exchange = 4;
pub const KEX_DH_GRP16_SHA512: kex_exchange = 3;
pub const KEX_DH_GRP14_SHA256: kex_exchange = 2;
pub const KEX_DH_GRP14_SHA1: kex_exchange = 1;
pub const KEX_DH_GRP1_SHA1: kex_exchange = 0;
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
pub struct C2RustUnnamed_6 {
    pub host_keys: *mut *mut sshkey,
    pub host_pubkeys: *mut *mut sshkey,
    pub host_certificates: *mut *mut sshkey,
    pub have_ssh2_key: libc::c_int,
}
pub static mut options: ServerOptions = ServerOptions {
    num_ports: 0,
    ports_from_cmdline: 0,
    ports: [0; 256],
    queued_listen_addrs: 0 as *const queued_listenaddr as *mut queued_listenaddr,
    num_queued_listens: 0,
    listen_addrs: 0 as *const listenaddr as *mut listenaddr,
    num_listen_addrs: 0,
    address_family: 0,
    routing_domain: 0 as *const libc::c_char as *mut libc::c_char,
    host_key_files: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    host_key_file_userprovided: 0 as *const libc::c_int as *mut libc::c_int,
    num_host_key_files: 0,
    host_cert_files: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    num_host_cert_files: 0,
    host_key_agent: 0 as *const libc::c_char as *mut libc::c_char,
    pid_file: 0 as *const libc::c_char as *mut libc::c_char,
    moduli_file: 0 as *const libc::c_char as *mut libc::c_char,
    login_grace_time: 0,
    permit_root_login: 0,
    ignore_rhosts: 0,
    ignore_user_known_hosts: 0,
    print_motd: 0,
    print_lastlog: 0,
    x11_forwarding: 0,
    x11_display_offset: 0,
    x11_use_localhost: 0,
    xauth_location: 0 as *const libc::c_char as *mut libc::c_char,
    permit_tty: 0,
    permit_user_rc: 0,
    strict_modes: 0,
    tcp_keep_alive: 0,
    ip_qos_interactive: 0,
    ip_qos_bulk: 0,
    ciphers: 0 as *const libc::c_char as *mut libc::c_char,
    macs: 0 as *const libc::c_char as *mut libc::c_char,
    kex_algorithms: 0 as *const libc::c_char as *mut libc::c_char,
    fwd_opts: ForwardOptions {
        gateway_ports: 0,
        streamlocal_bind_mask: 0,
        streamlocal_bind_unlink: 0,
    },
    log_facility: SYSLOG_FACILITY_DAEMON,
    log_level: SYSLOG_LEVEL_QUIET,
    num_log_verbose: 0,
    log_verbose: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    hostbased_authentication: 0,
    hostbased_uses_name_from_packet_only: 0,
    hostbased_accepted_algos: 0 as *const libc::c_char as *mut libc::c_char,
    hostkeyalgorithms: 0 as *const libc::c_char as *mut libc::c_char,
    ca_sign_algorithms: 0 as *const libc::c_char as *mut libc::c_char,
    pubkey_authentication: 0,
    pubkey_accepted_algos: 0 as *const libc::c_char as *mut libc::c_char,
    pubkey_auth_options: 0,
    kerberos_authentication: 0,
    kerberos_or_local_passwd: 0,
    kerberos_ticket_cleanup: 0,
    kerberos_get_afs_token: 0,
    gss_authentication: 0,
    gss_cleanup_creds: 0,
    gss_strict_acceptor: 0,
    password_authentication: 0,
    kbd_interactive_authentication: 0,
    permit_empty_passwd: 0,
    permit_user_env: 0,
    permit_user_env_allowlist: 0 as *const libc::c_char as *mut libc::c_char,
    compression: 0,
    allow_tcp_forwarding: 0,
    allow_streamlocal_forwarding: 0,
    allow_agent_forwarding: 0,
    disable_forwarding: 0,
    num_allow_users: 0,
    allow_users: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    num_deny_users: 0,
    deny_users: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    num_allow_groups: 0,
    allow_groups: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    num_deny_groups: 0,
    deny_groups: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    num_subsystems: 0,
    subsystem_name: [0 as *const libc::c_char as *mut libc::c_char; 256],
    subsystem_command: [0 as *const libc::c_char as *mut libc::c_char; 256],
    subsystem_args: [0 as *const libc::c_char as *mut libc::c_char; 256],
    num_accept_env: 0,
    accept_env: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    num_setenv: 0,
    setenv: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    max_startups_begin: 0,
    max_startups_rate: 0,
    max_startups: 0,
    per_source_max_startups: 0,
    per_source_masklen_ipv4: 0,
    per_source_masklen_ipv6: 0,
    max_authtries: 0,
    max_sessions: 0,
    banner: 0 as *const libc::c_char as *mut libc::c_char,
    use_dns: 0,
    client_alive_interval: 0,
    client_alive_count_max: 0,
    num_authkeys_files: 0,
    authorized_keys_files: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    adm_forced_command: 0 as *const libc::c_char as *mut libc::c_char,
    use_pam: 0,
    permit_tun: 0,
    permitted_opens: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    num_permitted_opens: 0,
    permitted_listens: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    num_permitted_listens: 0,
    chroot_directory: 0 as *const libc::c_char as *mut libc::c_char,
    revoked_keys_file: 0 as *const libc::c_char as *mut libc::c_char,
    trusted_user_ca_keys: 0 as *const libc::c_char as *mut libc::c_char,
    authorized_keys_command: 0 as *const libc::c_char as *mut libc::c_char,
    authorized_keys_command_user: 0 as *const libc::c_char as *mut libc::c_char,
    authorized_principals_file: 0 as *const libc::c_char as *mut libc::c_char,
    authorized_principals_command: 0 as *const libc::c_char as *mut libc::c_char,
    authorized_principals_command_user: 0 as *const libc::c_char as *mut libc::c_char,
    rekey_limit: 0,
    rekey_interval: 0,
    version_addendum: 0 as *const libc::c_char as *mut libc::c_char,
    num_auth_methods: 0,
    auth_methods: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    fingerprint_hash: 0,
    expose_userauth_info: 0,
    timing_secret: 0,
    sk_provider: 0 as *const libc::c_char as *mut libc::c_char,
    required_rsa_size: 0,
    channel_timeouts: 0 as *const *mut libc::c_char as *mut *mut libc::c_char,
    num_channel_timeouts: 0,
    unused_connection_timeout: 0,
};
pub static mut config_file_name: *mut libc::c_char =
    b"/usr/local/etc/sshd_config\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
pub static mut debug_flag: libc::c_int = 0 as libc::c_int;
static mut test_flag: libc::c_int = 0 as libc::c_int;
static mut inetd_flag: libc::c_int = 0 as libc::c_int;
static mut no_daemon_flag: libc::c_int = 0 as libc::c_int;
static mut log_stderr: libc::c_int = 0 as libc::c_int;
static mut saved_argv: *mut *mut libc::c_char =
    0 as *const *mut libc::c_char as *mut *mut libc::c_char;
static mut saved_argc: libc::c_int = 0;
static mut rexeced_flag: libc::c_int = 0 as libc::c_int;
static mut rexec_flag: libc::c_int = 1 as libc::c_int;
static mut rexec_argc: libc::c_int = 0 as libc::c_int;
static mut rexec_argv: *mut *mut libc::c_char =
    0 as *const *mut libc::c_char as *mut *mut libc::c_char;
static mut listen_socks: [libc::c_int; 16] = [0; 16];
static mut num_listen_socks: libc::c_int = 0 as libc::c_int;
pub static mut auth_sock: libc::c_int = -(1 as libc::c_int);
static mut have_agent: libc::c_int = 0 as libc::c_int;
pub static mut sensitive_data: C2RustUnnamed_6 = C2RustUnnamed_6 {
    host_keys: 0 as *const *mut sshkey as *mut *mut sshkey,
    host_pubkeys: 0 as *const *mut sshkey as *mut *mut sshkey,
    host_certificates: 0 as *const *mut sshkey as *mut *mut sshkey,
    have_ssh2_key: 0,
};
static mut received_sighup: sig_atomic_t = 0 as libc::c_int;
static mut received_sigterm: sig_atomic_t = 0 as libc::c_int;
pub static mut utmp_len: u_int = (64 as libc::c_int + 1 as libc::c_int) as u_int;
static mut startup_pipes: *mut libc::c_int = 0 as *const libc::c_int as *mut libc::c_int;
static mut startup_flags: *mut libc::c_int = 0 as *const libc::c_int as *mut libc::c_int;
static mut startup_pipe: libc::c_int = -(1 as libc::c_int);
pub static mut use_privsep: libc::c_int = -(1 as libc::c_int);
pub static mut pmonitor: *mut monitor = 0 as *const monitor as *mut monitor;
pub static mut privsep_is_preauth: libc::c_int = 1 as libc::c_int;
static mut privsep_chroot: libc::c_int = 1 as libc::c_int;
pub static mut the_authctxt: *mut Authctxt = 0 as *const Authctxt as *mut Authctxt;
pub static mut the_active_state: *mut ssh = 0 as *const ssh as *mut ssh;
pub static mut auth_opts: *mut sshauthopt = 0 as *const sshauthopt as *mut sshauthopt;
pub static mut cfg: *mut sshbuf = 0 as *const sshbuf as *mut sshbuf;
pub static mut includes: include_list = include_list {
    tqh_first: 0 as *const include_item as *mut include_item,
    tqh_last: 0 as *const *mut include_item as *mut *mut include_item,
};
pub static mut loginmsg: *mut sshbuf = 0 as *const sshbuf as *mut sshbuf;
pub static mut privsep_pw: *mut libc::passwd = 0 as *const libc::passwd as *mut libc::passwd;
static mut listener_proctitle: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
unsafe extern "C" fn close_listen_socks() {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < num_listen_socks {
        close(listen_socks[i as usize]);
        i += 1;
        i;
    }
    num_listen_socks = 0 as libc::c_int;
}
unsafe extern "C" fn close_startup_pipes() {
    let mut i: libc::c_int = 0;
    if !startup_pipes.is_null() {
        i = 0 as libc::c_int;
        while i < options.max_startups {
            if *startup_pipes.offset(i as isize) != -(1 as libc::c_int) {
                close(*startup_pipes.offset(i as isize));
            }
            i += 1;
            i;
        }
    }
}
unsafe extern "C" fn sighup_handler(mut _sig: libc::c_int) {
    ::core::ptr::write_volatile(&mut received_sighup as *mut sig_atomic_t, 1 as libc::c_int);
}
unsafe extern "C" fn sighup_restart() {
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sighup_restart\0")).as_ptr(),
        310 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"Received SIGHUP; restarting.\0" as *const u8 as *const libc::c_char,
    );
    if !(options.pid_file).is_null() {
        unlink(options.pid_file);
    }
    platform_pre_restart();
    close_listen_socks();
    close_startup_pipes();
    crate::misc::ssh_signal(
        1 as libc::c_int,
        ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
            1 as libc::c_int as libc::intptr_t,
        ),
    );
    execv(
        *saved_argv.offset(0 as libc::c_int as isize),
        saved_argv as *const *mut libc::c_char,
    );
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sighup_restart\0")).as_ptr(),
        319 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"RESTART FAILED: av[0]='%.100s', error: %.100s.\0" as *const u8 as *const libc::c_char,
        *saved_argv.offset(0 as libc::c_int as isize),
        strerror(*libc::__errno_location()),
    );
    libc::exit(1 as libc::c_int);
}
unsafe extern "C" fn sigterm_handler(mut sig: libc::c_int) {
    ::core::ptr::write_volatile(&mut received_sigterm as *mut sig_atomic_t, sig);
}
unsafe extern "C" fn main_sigchld_handler(mut _sig: libc::c_int) {
    let mut save_errno: libc::c_int = *libc::__errno_location();
    let mut pid: pid_t = 0;
    let mut status: libc::c_int = 0;
    loop {
        pid = libc::waitpid(-(1 as libc::c_int), &mut status, 1 as libc::c_int);
        if !(pid > 0 as libc::c_int
            || pid == -(1 as libc::c_int) && *libc::__errno_location() == 4 as libc::c_int)
        {
            break;
        }
    }
    *libc::__errno_location() = save_errno;
}
unsafe extern "C" fn grace_alarm_handler(mut _sig: libc::c_int) {
    if getpgid(0 as libc::c_int) == libc::getpid() {
        crate::misc::ssh_signal(
            15 as libc::c_int,
            ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
                1 as libc::c_int as libc::intptr_t,
            ),
        );
        kill(0 as libc::c_int, 15 as libc::c_int);
    }
    sshsigdie(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"grace_alarm_handler\0"))
            .as_ptr(),
        367 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"Timeout before authentication for %s port %d\0" as *const u8 as *const libc::c_char,
        ssh_remote_ipaddr(the_active_state),
        ssh_remote_port(the_active_state),
    );
}
pub unsafe extern "C" fn destroy_sensitive_data() {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < options.num_host_key_files {
        if !(*(sensitive_data.host_keys).offset(i as isize)).is_null() {
            sshkey_free(*(sensitive_data.host_keys).offset(i as isize));
            let ref mut fresh0 = *(sensitive_data.host_keys).offset(i as isize);
            *fresh0 = 0 as *mut sshkey;
        }
        if !(*(sensitive_data.host_certificates).offset(i as isize)).is_null() {
            sshkey_free(*(sensitive_data.host_certificates).offset(i as isize));
            let ref mut fresh1 = *(sensitive_data.host_certificates).offset(i as isize);
            *fresh1 = 0 as *mut sshkey;
        }
        i = i.wrapping_add(1);
        i;
    }
}
pub unsafe extern "C" fn demote_sensitive_data() {
    let mut tmp: *mut sshkey = 0 as *mut sshkey;
    let mut i: u_int = 0;
    let mut r: libc::c_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < options.num_host_key_files {
        if !(*(sensitive_data.host_keys).offset(i as isize)).is_null() {
            r = sshkey_from_private(*(sensitive_data.host_keys).offset(i as isize), &mut tmp);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"demote_sensitive_data\0",
                    ))
                    .as_ptr(),
                    401 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"could not demote host %s key\0" as *const u8 as *const libc::c_char,
                    sshkey_type(*(sensitive_data.host_keys).offset(i as isize)),
                );
            }
            sshkey_free(*(sensitive_data.host_keys).offset(i as isize));
            let ref mut fresh2 = *(sensitive_data.host_keys).offset(i as isize);
            *fresh2 = tmp;
        }
        i = i.wrapping_add(1);
        i;
    }
}
unsafe extern "C" fn reseed_prngs() {
    let mut rnd: [u_int32_t; 256] = [0; 256];
    RAND_poll();
    arc4random_buf(
        rnd.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_int32_t; 256]>() as libc::c_ulong,
    );
    RAND_seed(
        rnd.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[u_int32_t; 256]>() as libc::c_ulong as libc::c_int,
    );
    if RAND_bytes(rnd.as_mut_ptr() as *mut u_char, 1 as libc::c_int) != 1 as libc::c_int {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"reseed_prngs\0")).as_ptr(),
            424 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: RAND_bytes failed\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"reseed_prngs\0")).as_ptr(),
        );
    }
    explicit_bzero(
        rnd.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[u_int32_t; 256]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn privsep_preauth_child() {
    let mut gidset: [gid_t; 1] = [0; 1];
    privsep_challenge_enable();
    reseed_prngs();
    demote_sensitive_data();
    if privsep_chroot != 0 {
        if chroot(b"/var/empty\0" as *const u8 as *const libc::c_char) == -(1 as libc::c_int) {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"privsep_preauth_child\0",
                ))
                .as_ptr(),
                453 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"chroot(\"%s\"): %s\0" as *const u8 as *const libc::c_char,
                b"/var/empty\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
        if chdir(b"/\0" as *const u8 as *const libc::c_char) == -(1 as libc::c_int) {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"privsep_preauth_child\0",
                ))
                .as_ptr(),
                455 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"chdir(\"/\"): %s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"privsep_preauth_child\0"))
                .as_ptr(),
            459 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"privsep user:group %u:%u\0" as *const u8 as *const libc::c_char,
            (*privsep_pw).pw_uid,
            (*privsep_pw).pw_gid,
        );
        gidset[0 as libc::c_int as usize] = (*privsep_pw).pw_gid;
        if setgroups(1 as libc::c_int as size_t, gidset.as_mut_ptr()) == -(1 as libc::c_int) {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"privsep_preauth_child\0",
                ))
                .as_ptr(),
                462 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"setgroups: %.100s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
        permanently_set_uid(privsep_pw);
    }
}
unsafe extern "C" fn privsep_preauth(mut ssh: *mut ssh) -> libc::c_int {
    let mut status: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut pid: pid_t = 0;
    let mut box_0: *mut ssh_sandbox = 0 as *mut ssh_sandbox;
    pmonitor = monitor_init();
    (*pmonitor).m_pkex = &mut (*ssh).kex;
    if use_privsep == 1 as libc::c_int {
        box_0 = ssh_sandbox_init(pmonitor);
    }
    pid = libc::fork();
    if pid == -(1 as libc::c_int) {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"privsep_preauth\0"))
                .as_ptr(),
            483 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::fork of unprivileged child failed\0" as *const u8 as *const libc::c_char,
        );
    } else if pid != 0 as libc::c_int {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"privsep_preauth\0"))
                .as_ptr(),
            485 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"Network child is on pid %ld\0" as *const u8 as *const libc::c_char,
            pid as libc::c_long,
        );
        (*pmonitor).m_pid = pid;
        if have_agent != 0 {
            r = ssh_get_authentication_socket(&mut auth_sock);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"privsep_preauth\0",
                    ))
                    .as_ptr(),
                    491 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"Could not get agent socket\0" as *const u8 as *const libc::c_char,
                );
                have_agent = 0 as libc::c_int;
            }
        }
        if !box_0.is_null() {
            ssh_sandbox_parent_preauth(box_0, pid);
        }
        monitor_child_preauth(ssh, pmonitor);
        while libc::waitpid(pid, &mut status, 0 as libc::c_int) == -(1 as libc::c_int) {
            if *libc::__errno_location() == 4 as libc::c_int {
                continue;
            }
            (*pmonitor).m_pid = -(1 as libc::c_int);
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"privsep_preauth\0"))
                    .as_ptr(),
                504 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"libc::waitpid: %s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
        privsep_is_preauth = 0 as libc::c_int;
        (*pmonitor).m_pid = -(1 as libc::c_int);
        if status & 0x7f as libc::c_int == 0 as libc::c_int {
            if (status & 0xff00 as libc::c_int) >> 8 as libc::c_int != 0 as libc::c_int {
                sshfatal(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"privsep_preauth\0",
                    ))
                    .as_ptr(),
                    511 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"preauth child exited with status %d\0" as *const u8 as *const libc::c_char,
                    (status & 0xff00 as libc::c_int) >> 8 as libc::c_int,
                );
            }
        } else if ((status & 0x7f as libc::c_int) + 1 as libc::c_int) as libc::c_schar
            as libc::c_int
            >> 1 as libc::c_int
            > 0 as libc::c_int
        {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"privsep_preauth\0"))
                    .as_ptr(),
                514 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"preauth child terminated by signal %d\0" as *const u8 as *const libc::c_char,
                status & 0x7f as libc::c_int,
            );
        }
        if !box_0.is_null() {
            ssh_sandbox_parent_finish(box_0);
        }
        return 1 as libc::c_int;
    } else {
        close((*pmonitor).m_sendfd);
        close((*pmonitor).m_log_recvfd);
        set_log_handler(
            Some(
                mm_log_handler
                    as unsafe extern "C" fn(
                        LogLevel,
                        libc::c_int,
                        *const libc::c_char,
                        *mut libc::c_void,
                    ) -> (),
            ),
            pmonitor as *mut libc::c_void,
        );
        privsep_preauth_child();
        setproctitle(
            b"%s\0" as *const u8 as *const libc::c_char,
            b"[net]\0" as *const u8 as *const libc::c_char,
        );
        if !box_0.is_null() {
            ssh_sandbox_child(box_0);
        }
        return 0 as libc::c_int;
    };
}
unsafe extern "C" fn privsep_postauth(mut ssh: *mut ssh, mut authctxt: *mut Authctxt) {
    if (*(*authctxt).pw).pw_uid == 0 as libc::c_int as libc::c_uint {
        use_privsep = 0 as libc::c_int;
    } else {
        monitor_reinit(pmonitor);
        (*pmonitor).m_pid = libc::fork();
        if (*pmonitor).m_pid == -(1 as libc::c_int) {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"privsep_postauth\0"))
                    .as_ptr(),
                553 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"libc::fork of unprivileged child failed\0" as *const u8 as *const libc::c_char,
            );
        } else if (*pmonitor).m_pid != 0 as libc::c_int {
            crate::log::sshlog(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"privsep_postauth\0"))
                    .as_ptr(),
                555 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_VERBOSE,
                0 as *const libc::c_char,
                b"User child is on pid %ld\0" as *const u8 as *const libc::c_char,
                (*pmonitor).m_pid as libc::c_long,
            );
            sshbuf_reset(loginmsg);
            monitor_clear_keystate(ssh, pmonitor);
            monitor_child_postauth(ssh, pmonitor);
            libc::exit(0 as libc::c_int);
        }
        close((*pmonitor).m_sendfd);
        (*pmonitor).m_sendfd = -(1 as libc::c_int);
        demote_sensitive_data();
        reseed_prngs();
        do_setusercontext((*authctxt).pw);
    }
    monitor_apply_keystate(ssh, pmonitor);
    ssh_packet_set_authenticated(ssh);
}
unsafe extern "C" fn append_hostkey_type(mut b: *mut sshbuf, mut s: *const libc::c_char) {
    let mut r: libc::c_int = 0;
    if match_pattern_list(s, options.hostkeyalgorithms, 0 as libc::c_int) != 1 as libc::c_int {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"append_hostkey_type\0"))
                .as_ptr(),
            594 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"%s key not permitted by HostkeyAlgorithms\0" as *const u8 as *const libc::c_char,
            s,
        );
        return;
    }
    r = sshbuf_putf(
        b,
        b"%s%s\0" as *const u8 as *const libc::c_char,
        if sshbuf_len(b) > 0 as libc::c_int as libc::c_ulong {
            b",\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        s,
    );
    if r != 0 as libc::c_int {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"append_hostkey_type\0"))
                .as_ptr(),
            598 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"sshbuf_putf\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn list_hostkey_types() -> *mut libc::c_char {
    let mut b: *mut sshbuf = 0 as *mut sshbuf;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: u_int = 0;
    b = sshbuf_new();
    if b.is_null() {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"list_hostkey_types\0"))
                .as_ptr(),
            610 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_host_key_files {
        key = *(sensitive_data.host_keys).offset(i as isize);
        if key.is_null() {
            key = *(sensitive_data.host_pubkeys).offset(i as isize);
        }
        if !key.is_null() {
            let mut current_block_8: u64;
            match (*key).type_0 {
                0 => {
                    append_hostkey_type(b, b"rsa-sha2-512\0" as *const u8 as *const libc::c_char);
                    append_hostkey_type(b, b"rsa-sha2-256\0" as *const u8 as *const libc::c_char);
                    current_block_8 = 9661063118910216952;
                }
                1 | 2 | 3 | 10 | 12 | 8 => {
                    current_block_8 = 9661063118910216952;
                }
                _ => {
                    current_block_8 = 10599921512955367680;
                }
            }
            match current_block_8 {
                9661063118910216952 => {
                    append_hostkey_type(b, sshkey_ssh_name(key));
                }
                _ => {}
            }
            key = *(sensitive_data.host_certificates).offset(i as isize);
            if !key.is_null() {
                let mut current_block_13: u64;
                match (*key).type_0 {
                    4 => {
                        append_hostkey_type(
                            b,
                            b"rsa-sha2-512-cert-v01@openssh.com\0" as *const u8
                                as *const libc::c_char,
                        );
                        append_hostkey_type(
                            b,
                            b"rsa-sha2-256-cert-v01@openssh.com\0" as *const u8
                                as *const libc::c_char,
                        );
                        current_block_13 = 9607677670342416640;
                    }
                    5 | 6 | 7 | 11 | 13 | 9 => {
                        current_block_13 = 9607677670342416640;
                    }
                    _ => {
                        current_block_13 = 4495394744059808450;
                    }
                }
                match current_block_13 {
                    9607677670342416640 => {
                        append_hostkey_type(b, sshkey_ssh_name(key));
                    }
                    _ => {}
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    ret = sshbuf_dup_string(b);
    if ret.is_null() {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"list_hostkey_types\0"))
                .as_ptr(),
            655 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_dup_string failed\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(b);
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"list_hostkey_types\0"))
            .as_ptr(),
        657 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"%s\0" as *const u8 as *const libc::c_char,
        ret,
    );
    return ret;
}
unsafe extern "C" fn get_hostkey_by_type(
    mut type_0: libc::c_int,
    mut nid: libc::c_int,
    mut need_private: libc::c_int,
    mut _ssh: *mut ssh,
) -> *mut sshkey {
    let mut i: u_int = 0;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut current_block_6: u64;
    i = 0 as libc::c_int as u_int;
    while i < options.num_host_key_files {
        match type_0 {
            4 | 5 | 6 | 7 | 11 | 13 | 9 => {
                key = *(sensitive_data.host_certificates).offset(i as isize);
            }
            _ => {
                key = *(sensitive_data.host_keys).offset(i as isize);
                if key.is_null() && need_private == 0 {
                    key = *(sensitive_data.host_pubkeys).offset(i as isize);
                }
            }
        }
        if !(key.is_null() || (*key).type_0 != type_0) {
            match type_0 {
                2 | 10 | 6 | 11 => {
                    if (*key).ecdsa_nid != nid {
                        current_block_6 = 16668937799742929182;
                    } else {
                        current_block_6 = 16718028820253999673;
                    }
                }
                _ => {
                    current_block_6 = 16718028820253999673;
                }
            }
            match current_block_6 {
                16668937799742929182 => {}
                _ => {
                    return if need_private != 0 {
                        *(sensitive_data.host_keys).offset(i as isize)
                    } else {
                        key
                    };
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as *mut sshkey;
}
pub unsafe extern "C" fn get_hostkey_public_by_type(
    mut type_0: libc::c_int,
    mut nid: libc::c_int,
    mut ssh: *mut ssh,
) -> *mut sshkey {
    return get_hostkey_by_type(type_0, nid, 0 as libc::c_int, ssh);
}
pub unsafe extern "C" fn get_hostkey_private_by_type(
    mut type_0: libc::c_int,
    mut nid: libc::c_int,
    mut ssh: *mut ssh,
) -> *mut sshkey {
    return get_hostkey_by_type(type_0, nid, 1 as libc::c_int, ssh);
}
pub unsafe extern "C" fn get_hostkey_by_index(mut ind: libc::c_int) -> *mut sshkey {
    if ind < 0 as libc::c_int || ind as u_int >= options.num_host_key_files {
        return 0 as *mut sshkey;
    }
    return *(sensitive_data.host_keys).offset(ind as isize);
}
pub unsafe extern "C" fn get_hostkey_public_by_index(
    mut ind: libc::c_int,
    mut _ssh: *mut ssh,
) -> *mut sshkey {
    if ind < 0 as libc::c_int || ind as u_int >= options.num_host_key_files {
        return 0 as *mut sshkey;
    }
    return *(sensitive_data.host_pubkeys).offset(ind as isize);
}
pub unsafe extern "C" fn get_hostkey_index(
    mut key: *mut sshkey,
    mut compare: libc::c_int,
    mut _ssh: *mut ssh,
) -> libc::c_int {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < options.num_host_key_files {
        if sshkey_is_cert(key) != 0 {
            if key == *(sensitive_data.host_certificates).offset(i as isize)
                || compare != 0
                    && !(*(sensitive_data.host_certificates).offset(i as isize)).is_null()
                    && sshkey_equal(key, *(sensitive_data.host_certificates).offset(i as isize))
                        != 0
            {
                return i as libc::c_int;
            }
        } else {
            if key == *(sensitive_data.host_keys).offset(i as isize)
                || compare != 0
                    && !(*(sensitive_data.host_keys).offset(i as isize)).is_null()
                    && sshkey_equal(key, *(sensitive_data.host_keys).offset(i as isize)) != 0
            {
                return i as libc::c_int;
            }
            if key == *(sensitive_data.host_pubkeys).offset(i as isize)
                || compare != 0
                    && !(*(sensitive_data.host_pubkeys).offset(i as isize)).is_null()
                    && sshkey_equal(key, *(sensitive_data.host_pubkeys).offset(i as isize)) != 0
            {
                return i as libc::c_int;
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn notify_hostkeys(mut ssh: *mut ssh) {
    let mut buf: *mut sshbuf = 0 as *mut sshbuf;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut i: u_int = 0;
    let mut nkeys: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    if (*ssh).compat & 0x20000000 as libc::c_int != 0 {
        return;
    }
    buf = sshbuf_new();
    if buf.is_null() {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"notify_hostkeys\0"))
                .as_ptr(),
            771 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new\0" as *const u8 as *const libc::c_char,
        );
    }
    nkeys = 0 as libc::c_int as u_int;
    i = nkeys;
    while i < options.num_host_key_files {
        key = get_hostkey_public_by_index(i as libc::c_int, ssh);
        if !(key.is_null()
            || (*key).type_0 == KEY_UNSPEC as libc::c_int
            || sshkey_is_cert(key) != 0)
        {
            fp = sshkey_fingerprint(key, options.fingerprint_hash, SSH_FP_DEFAULT);
            crate::log::sshlog(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"notify_hostkeys\0"))
                    .as_ptr(),
                779 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"key %d: %s %s\0" as *const u8 as *const libc::c_char,
                i,
                sshkey_ssh_name(key),
                fp,
            );
            libc::free(fp as *mut libc::c_void);
            if nkeys == 0 as libc::c_int as libc::c_uint {
                r = sshpkt_start(ssh, 80 as libc::c_int as u_char);
                if r != 0 as libc::c_int
                    || {
                        r = sshpkt_put_cstring(
                            ssh,
                            b"hostkeys-00@openssh.com\0" as *const u8 as *const libc::c_char
                                as *const libc::c_void,
                        );
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshpkt_put_u8(ssh, 0 as libc::c_int as u_char);
                        r != 0 as libc::c_int
                    }
                {
                    sshpkt_fatal(
                        ssh,
                        r,
                        b"%s: start request\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"notify_hostkeys\0",
                        ))
                        .as_ptr(),
                    );
                }
            }
            sshbuf_reset(buf);
            r = sshkey_putb(key, buf);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"notify_hostkeys\0",
                    ))
                    .as_ptr(),
                    794 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"couldn't put hostkey %d\0" as *const u8 as *const libc::c_char,
                    i,
                );
            }
            r = sshpkt_put_stringb(ssh, buf);
            if r != 0 as libc::c_int {
                sshpkt_fatal(
                    ssh,
                    r,
                    b"%s: append key\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"notify_hostkeys\0",
                    ))
                    .as_ptr(),
                );
            }
            nkeys = nkeys.wrapping_add(1);
            nkeys;
        }
        i = i.wrapping_add(1);
        i;
    }
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"notify_hostkeys\0")).as_ptr(),
        799 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"sent %u hostkeys\0" as *const u8 as *const libc::c_char,
        nkeys,
    );
    if nkeys == 0 as libc::c_int as libc::c_uint {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"notify_hostkeys\0"))
                .as_ptr(),
            801 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no hostkeys\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshpkt_send(ssh);
    if r != 0 as libc::c_int {
        sshpkt_fatal(
            ssh,
            r,
            b"%s: send\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"notify_hostkeys\0"))
                .as_ptr(),
        );
    }
    sshbuf_free(buf);
}
unsafe extern "C" fn should_drop_connection(mut startups: libc::c_int) -> libc::c_int {
    let mut p: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    if startups < options.max_startups_begin {
        return 0 as libc::c_int;
    }
    if startups >= options.max_startups {
        return 1 as libc::c_int;
    }
    if options.max_startups_rate == 100 as libc::c_int {
        return 1 as libc::c_int;
    }
    p = 100 as libc::c_int - options.max_startups_rate;
    p *= startups - options.max_startups_begin;
    p /= options.max_startups - options.max_startups_begin;
    p += options.max_startups_rate;
    r = arc4random_uniform(100 as libc::c_int as uint32_t) as libc::c_int;
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"should_drop_connection\0"))
            .as_ptr(),
        831 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"p %d, r %d\0" as *const u8 as *const libc::c_char,
        p,
        r,
    );
    return if r < p {
        1 as libc::c_int
    } else {
        0 as libc::c_int
    };
}
unsafe extern "C" fn drop_connection(
    mut sock: libc::c_int,
    mut startups: libc::c_int,
    mut notify_pipe: libc::c_int,
) -> libc::c_int {
    let mut laddr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut raddr: *mut libc::c_char = 0 as *mut libc::c_char;
    let msg: [libc::c_char; 23] =
        *::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"Exceeded MaxStartups\r\n\0");
    static mut last_drop: time_t = 0;
    static mut first_drop: time_t = 0;
    static mut ndropped: u_int = 0;
    let mut drop_level: LogLevel = SYSLOG_LEVEL_VERBOSE;
    let mut now: time_t = 0;
    now = monotime();
    if should_drop_connection(startups) == 0
        && srclimit_check_allow(sock, notify_pipe) == 1 as libc::c_int
    {
        if last_drop != 0 as libc::c_int as libc::c_long
            && startups < options.max_startups_begin - 1 as libc::c_int
        {
            crate::log::sshlog(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"drop_connection\0"))
                    .as_ptr(),
                860 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"exited MaxStartups throttling after %s, %u connections dropped\0" as *const u8
                    as *const libc::c_char,
                fmt_timeframe(now - first_drop),
                ndropped,
            );
            last_drop = 0 as libc::c_int as time_t;
        }
        return 0 as libc::c_int;
    }
    if last_drop == 0 as libc::c_int as libc::c_long {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"drop_connection\0"))
                .as_ptr(),
            868 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"beginning MaxStartups throttling\0" as *const u8 as *const libc::c_char,
        );
        drop_level = SYSLOG_LEVEL_INFO;
        first_drop = now;
        ndropped = 0 as libc::c_int as u_int;
    } else if (last_drop + (5 as libc::c_int * 60 as libc::c_int) as libc::c_long) < now {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"drop_connection\0"))
                .as_ptr(),
            876 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"in MaxStartups throttling for %s, %u connections dropped\0" as *const u8
                as *const libc::c_char,
            fmt_timeframe(now - first_drop),
            ndropped.wrapping_add(1 as libc::c_int as libc::c_uint),
        );
        drop_level = SYSLOG_LEVEL_INFO;
    }
    last_drop = now;
    ndropped = ndropped.wrapping_add(1);
    ndropped;
    laddr = get_local_ipaddr(sock);
    raddr = get_peer_ipaddr(sock);
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"drop_connection\0")).as_ptr(),
        886 as libc::c_int,
        0 as libc::c_int,
        drop_level,
        0 as *const libc::c_char,
        b"drop connection #%d from [%s]:%d on [%s]:%d past MaxStartups\0" as *const u8
            as *const libc::c_char,
        startups,
        raddr,
        get_peer_port(sock),
        laddr,
        get_local_port(sock),
    );
    libc::free(laddr as *mut libc::c_void);
    libc::free(raddr as *mut libc::c_void);
    write(
        sock,
        msg.as_ptr() as *const libc::c_void,
        (::core::mem::size_of::<[libc::c_char; 23]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    );
    return 1 as libc::c_int;
}
unsafe extern "C" fn usage() {
    libc::fprintf(
        stderr,
        b"%s, %s\n\0" as *const u8 as *const libc::c_char,
        b"OpenSSH_9.3p1\0" as *const u8 as *const libc::c_char,
        OpenSSL_version(0 as libc::c_int),
    );
    libc::fprintf(
        stderr,
        b"usage: sshd [-46DdeGiqTtV] [-C connection_spec] [-c host_cert_file]\n            [-E log_file] [-f config_file] [-g login_grace_time]\n            [-h host_key_file] [-o option] [-p port] [-u len]\n\0"
            as *const u8 as *const libc::c_char,
    );
    libc::exit(1 as libc::c_int);
}
unsafe extern "C" fn send_rexec_state(mut fd: libc::c_int, mut conf: *mut sshbuf) {
    let mut m: *mut sshbuf = 0 as *mut sshbuf;
    let mut inc: *mut sshbuf = 0 as *mut sshbuf;
    let mut item: *mut include_item = 0 as *mut include_item;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"send_rexec_state\0")).as_ptr(),
        914 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering fd = %d config len %zu\0" as *const u8 as *const libc::c_char,
        fd,
        sshbuf_len(conf),
    );
    m = sshbuf_new();
    if m.is_null() || {
        inc = sshbuf_new();
        inc.is_null()
    } {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"send_rexec_state\0"))
                .as_ptr(),
            917 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    item = includes.tqh_first;
    while !item.is_null() {
        r = sshbuf_put_cstring(inc, (*item).selector);
        if r != 0 as libc::c_int
            || {
                r = sshbuf_put_cstring(inc, (*item).filename);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put_stringb(inc, (*item).contents);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"send_rexec_state\0"))
                    .as_ptr(),
                924 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"compose includes\0" as *const u8 as *const libc::c_char,
            );
        }
        item = (*item).entry.tqe_next;
    }
    r = sshbuf_put_stringb(m, conf);
    if r != 0 as libc::c_int || {
        r = sshbuf_put_stringb(m, inc);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"send_rexec_state\0"))
                .as_ptr(),
            938 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"compose config\0" as *const u8 as *const libc::c_char,
        );
    }
    if ssh_msg_send(fd, 0 as libc::c_int as u_char, m) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"send_rexec_state\0"))
                .as_ptr(),
            940 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"ssh_msg_send failed\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(m);
    sshbuf_free(inc);
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"send_rexec_state\0")).as_ptr(),
        945 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"done\0" as *const u8 as *const libc::c_char,
    );
}
unsafe extern "C" fn recv_rexec_state(mut fd: libc::c_int, mut conf: *mut sshbuf) {
    let mut m: *mut sshbuf = 0 as *mut sshbuf;
    let mut inc: *mut sshbuf = 0 as *mut sshbuf;
    let mut cp: *mut u_char = 0 as *mut u_char;
    let mut ver: u_char = 0;
    let mut len: size_t = 0;
    let mut r: libc::c_int = 0;
    let mut item: *mut include_item = 0 as *mut include_item;
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"recv_rexec_state\0")).as_ptr(),
        957 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering fd = %d\0" as *const u8 as *const libc::c_char,
        fd,
    );
    m = sshbuf_new();
    if m.is_null() || {
        inc = sshbuf_new();
        inc.is_null()
    } {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"recv_rexec_state\0"))
                .as_ptr(),
            960 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    if ssh_msg_recv(fd, m) == -(1 as libc::c_int) {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"recv_rexec_state\0"))
                .as_ptr(),
            962 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ssh_msg_recv failed\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_get_u8(m, &mut ver);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"recv_rexec_state\0"))
                .as_ptr(),
            964 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse version\0" as *const u8 as *const libc::c_char,
        );
    }
    if ver as libc::c_int != 0 as libc::c_int {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"recv_rexec_state\0"))
                .as_ptr(),
            966 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"rexec version mismatch\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshbuf_get_string(m, &mut cp, &mut len);
    if r != 0 as libc::c_int || {
        r = sshbuf_get_stringb(m, inc);
        r != 0 as libc::c_int
    } {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"recv_rexec_state\0"))
                .as_ptr(),
            969 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"parse config\0" as *const u8 as *const libc::c_char,
        );
    }
    if !conf.is_null() && {
        r = sshbuf_put(conf, cp as *const libc::c_void, len);
        r != 0
    } {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"recv_rexec_state\0"))
                .as_ptr(),
            972 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"sshbuf_put\0" as *const u8 as *const libc::c_char,
        );
    }
    while sshbuf_len(inc) != 0 as libc::c_int as libc::c_ulong {
        item = xcalloc(
            1 as libc::c_int as size_t,
            ::core::mem::size_of::<include_item>() as libc::c_ulong,
        ) as *mut include_item;
        (*item).contents = sshbuf_new();
        if ((*item).contents).is_null() {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"recv_rexec_state\0"))
                    .as_ptr(),
                977 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
            );
        }
        r = sshbuf_get_cstring(inc, &mut (*item).selector, 0 as *mut size_t);
        if r != 0 as libc::c_int
            || {
                r = sshbuf_get_cstring(inc, &mut (*item).filename, 0 as *mut size_t);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_get_stringb(inc, (*item).contents);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"recv_rexec_state\0"))
                    .as_ptr(),
                981 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"parse includes\0" as *const u8 as *const libc::c_char,
            );
        }
        (*item).entry.tqe_next = 0 as *mut include_item;
        (*item).entry.tqe_prev = includes.tqh_last;
        *includes.tqh_last = item;
        includes.tqh_last = &mut (*item).entry.tqe_next;
    }
    libc::free(cp as *mut libc::c_void);
    sshbuf_free(m);
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"recv_rexec_state\0")).as_ptr(),
        988 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"done\0" as *const u8 as *const libc::c_char,
    );
}
unsafe extern "C" fn server_accept_inetd(
    mut sock_in: *mut libc::c_int,
    mut sock_out: *mut libc::c_int,
) {
    if rexeced_flag != 0 {
        close(2 as libc::c_int + 3 as libc::c_int);
        *sock_out = dup(0 as libc::c_int);
        *sock_in = *sock_out;
    } else {
        *sock_in = dup(0 as libc::c_int);
        *sock_out = dup(1 as libc::c_int);
    }
    if stdfd_devnull(
        1 as libc::c_int,
        1 as libc::c_int,
        (log_stderr == 0) as libc::c_int,
    ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"server_accept_inetd\0"))
                .as_ptr(),
            1008 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"stdfd_devnull failed\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"server_accept_inetd\0"))
            .as_ptr(),
        1009 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"inetd sockets after dupping: %d, %d\0" as *const u8 as *const libc::c_char,
        *sock_in,
        *sock_out,
    );
}
unsafe extern "C" fn listen_on_addrs(mut la: *mut listenaddr) {
    let mut ret: libc::c_int = 0;
    let mut listen_sock: libc::c_int = 0;
    let mut ai: *mut addrinfo = 0 as *mut addrinfo;
    let mut ntop: [libc::c_char; 1025] = [0; 1025];
    let mut strport: [libc::c_char; 32] = [0; 32];
    ai = (*la).addrs;
    while !ai.is_null() {
        if !((*ai).ai_family != 2 as libc::c_int && (*ai).ai_family != 10 as libc::c_int) {
            if num_listen_socks >= 16 as libc::c_int {
                sshfatal(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"listen_on_addrs\0",
                    ))
                    .as_ptr(),
                    1027 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Too many listen sockets. Enlarge MAX_LISTEN_SOCKS\0" as *const u8
                        as *const libc::c_char,
                );
            }
            ret = getnameinfo(
                (*ai).ai_addr,
                (*ai).ai_addrlen,
                ntop.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as socklen_t,
                strport.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong as socklen_t,
                1 as libc::c_int | 2 as libc::c_int,
            );
            if ret != 0 as libc::c_int {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"listen_on_addrs\0",
                    ))
                    .as_ptr(),
                    1032 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"getnameinfo failed: %.100s\0" as *const u8 as *const libc::c_char,
                    ssh_gai_strerror(ret),
                );
            } else {
                listen_sock = socket((*ai).ai_family, (*ai).ai_socktype, (*ai).ai_protocol);
                if listen_sock == -(1 as libc::c_int) {
                    crate::log::sshlog(
                        b"sshd.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"listen_on_addrs\0",
                        ))
                        .as_ptr(),
                        1040 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_VERBOSE,
                        0 as *const libc::c_char,
                        b"socket: %.100s\0" as *const u8 as *const libc::c_char,
                        strerror(*libc::__errno_location()),
                    );
                } else if crate::misc::set_nonblock(listen_sock) == -(1 as libc::c_int) {
                    close(listen_sock);
                } else if fcntl(listen_sock, 2 as libc::c_int, 1 as libc::c_int)
                    == -(1 as libc::c_int)
                {
                    crate::log::sshlog(
                        b"sshd.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"listen_on_addrs\0",
                        ))
                        .as_ptr(),
                        1048 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_VERBOSE,
                        0 as *const libc::c_char,
                        b"socket: CLOEXEC: %s\0" as *const u8 as *const libc::c_char,
                        strerror(*libc::__errno_location()),
                    );
                    close(listen_sock);
                } else {
                    set_reuseaddr(listen_sock);
                    if !((*la).rdomain).is_null()
                        && set_rdomain(listen_sock, (*la).rdomain) == -(1 as libc::c_int)
                    {
                        close(listen_sock);
                    } else {
                        if (*ai).ai_family == 10 as libc::c_int {
                            sock_set_v6only(listen_sock);
                        }
                        crate::log::sshlog(
                            b"sshd.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                b"listen_on_addrs\0",
                            ))
                            .as_ptr(),
                            1064 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"Bind to port %s on %s.\0" as *const u8 as *const libc::c_char,
                            strport.as_mut_ptr(),
                            ntop.as_mut_ptr(),
                        );
                        if bind(
                            listen_sock,
                            __CONST_SOCKADDR_ARG {
                                __sockaddr__: (*ai).ai_addr,
                            },
                            (*ai).ai_addrlen,
                        ) == -(1 as libc::c_int)
                        {
                            crate::log::sshlog(
                                b"sshd.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                    b"listen_on_addrs\0",
                                ))
                                .as_ptr(),
                                1069 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"Bind to port %s on %s failed: %.200s.\0" as *const u8
                                    as *const libc::c_char,
                                strport.as_mut_ptr(),
                                ntop.as_mut_ptr(),
                                strerror(*libc::__errno_location()),
                            );
                            close(listen_sock);
                        } else {
                            listen_socks[num_listen_socks as usize] = listen_sock;
                            num_listen_socks += 1;
                            num_listen_socks;
                            if listen(listen_sock, 128 as libc::c_int) == -(1 as libc::c_int) {
                                sshfatal(
                                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                        b"listen_on_addrs\0",
                                    ))
                                    .as_ptr(),
                                    1079 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    0 as *const libc::c_char,
                                    b"listen on [%s]:%s: %.100s\0" as *const u8
                                        as *const libc::c_char,
                                    ntop.as_mut_ptr(),
                                    strport.as_mut_ptr(),
                                    strerror(*libc::__errno_location()),
                                );
                            }
                            crate::log::sshlog(
                                b"sshd.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                                    b"listen_on_addrs\0",
                                ))
                                .as_ptr(),
                                1083 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_INFO,
                                0 as *const libc::c_char,
                                b"Server listening on %s port %s%s%s.\0" as *const u8
                                    as *const libc::c_char,
                                ntop.as_mut_ptr(),
                                strport.as_mut_ptr(),
                                if ((*la).rdomain).is_null() {
                                    b"\0" as *const u8 as *const libc::c_char
                                } else {
                                    b" rdomain \0" as *const u8 as *const libc::c_char
                                },
                                if ((*la).rdomain).is_null() {
                                    b"\0" as *const u8 as *const libc::c_char
                                } else {
                                    (*la).rdomain as *const libc::c_char
                                },
                            );
                        }
                    }
                }
            }
        }
        ai = (*ai).ai_next;
    }
}
unsafe extern "C" fn server_listen() {
    let mut i: u_int = 0;
    srclimit_init(
        options.max_startups,
        options.per_source_max_startups,
        options.per_source_masklen_ipv4,
        options.per_source_masklen_ipv6,
    );
    i = 0 as libc::c_int as u_int;
    while i < options.num_listen_addrs {
        listen_on_addrs(&mut *(options.listen_addrs).offset(i as isize));
        freeaddrinfo((*(options.listen_addrs).offset(i as isize)).addrs);
        libc::free((*(options.listen_addrs).offset(i as isize)).rdomain as *mut libc::c_void);
        memset(
            &mut *(options.listen_addrs).offset(i as isize) as *mut listenaddr as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<listenaddr>() as libc::c_ulong,
        );
        i = i.wrapping_add(1);
        i;
    }
    libc::free(options.listen_addrs as *mut libc::c_void);
    options.listen_addrs = 0 as *mut listenaddr;
    options.num_listen_addrs = 0 as libc::c_int as u_int;
    if num_listen_socks == 0 {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"server_listen\0"))
                .as_ptr(),
            1108 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Cannot bind any address.\0" as *const u8 as *const libc::c_char,
        );
    }
}
unsafe extern "C" fn server_accept_loop(
    mut sock_in: *mut libc::c_int,
    mut sock_out: *mut libc::c_int,
    mut newsock: *mut libc::c_int,
    mut config_s: *mut libc::c_int,
) {
    let mut pfd: *mut pollfd = 0 as *mut pollfd;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut npfd: libc::c_int = 0;
    let mut ostartups: libc::c_int = -(1 as libc::c_int);
    let mut startups: libc::c_int = 0 as libc::c_int;
    let mut listening: libc::c_int = 0 as libc::c_int;
    let mut lameduck: libc::c_int = 0 as libc::c_int;
    let mut startup_p: [libc::c_int; 2] = [-(1 as libc::c_int), -(1 as libc::c_int)];
    let mut startup_pollfd: *mut libc::c_int = 0 as *mut libc::c_int;
    let mut c: libc::c_char = 0 as libc::c_int as libc::c_char;
    let mut from: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut fromlen: socklen_t = 0;
    let mut pid: pid_t = 0;
    let mut rnd: [u_char; 256] = [0; 256];
    let mut nsigset: sigset_t = sigset_t { __val: [0; 16] };
    let mut osigset: sigset_t = sigset_t { __val: [0; 16] };
    startup_pipes = xcalloc(
        options.max_startups as size_t,
        ::core::mem::size_of::<libc::c_int>() as libc::c_ulong,
    ) as *mut libc::c_int;
    startup_flags = xcalloc(
        options.max_startups as size_t,
        ::core::mem::size_of::<libc::c_int>() as libc::c_ulong,
    ) as *mut libc::c_int;
    startup_pollfd = xcalloc(
        options.max_startups as size_t,
        ::core::mem::size_of::<libc::c_int>() as libc::c_ulong,
    ) as *mut libc::c_int;
    i = 0 as libc::c_int;
    while i < options.max_startups {
        *startup_pipes.offset(i as isize) = -(1 as libc::c_int);
        i += 1;
        i;
    }
    sigemptyset(&mut nsigset);
    sigaddset(&mut nsigset, 1 as libc::c_int);
    sigaddset(&mut nsigset, 17 as libc::c_int);
    sigaddset(&mut nsigset, 15 as libc::c_int);
    sigaddset(&mut nsigset, 3 as libc::c_int);
    pfd = xcalloc(
        (num_listen_socks + options.max_startups) as size_t,
        ::core::mem::size_of::<pollfd>() as libc::c_ulong,
    ) as *mut pollfd;
    loop {
        sigprocmask(0 as libc::c_int, &mut nsigset, &mut osigset);
        if received_sigterm != 0 {
            crate::log::sshlog(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"server_accept_loop\0",
                ))
                .as_ptr(),
                1160 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Received signal %d; terminating.\0" as *const u8 as *const libc::c_char,
                received_sigterm,
            );
            close_listen_socks();
            if !(options.pid_file).is_null() {
                unlink(options.pid_file);
            }
            libc::exit(if received_sigterm == 15 as libc::c_int {
                0 as libc::c_int
            } else {
                255 as libc::c_int
            });
        }
        if ostartups != startups {
            setproctitle(
                b"%s [listener] %d of %d-%d startups\0" as *const u8 as *const libc::c_char,
                listener_proctitle,
                startups,
                options.max_startups_begin,
                options.max_startups,
            );
            ostartups = startups;
        }
        if received_sighup != 0 {
            if lameduck == 0 {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"server_accept_loop\0",
                    ))
                    .as_ptr(),
                    1174 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"Received SIGHUP; waiting for children\0" as *const u8 as *const libc::c_char,
                );
                close_listen_socks();
                lameduck = 1 as libc::c_int;
            }
            if listening <= 0 as libc::c_int {
                sigprocmask(2 as libc::c_int, &mut osigset, 0 as *mut sigset_t);
                sighup_restart();
            }
        }
        i = 0 as libc::c_int;
        while i < num_listen_socks {
            (*pfd.offset(i as isize)).fd = listen_socks[i as usize];
            (*pfd.offset(i as isize)).events = 0x1 as libc::c_int as libc::c_short;
            i += 1;
            i;
        }
        npfd = num_listen_socks;
        i = 0 as libc::c_int;
        while i < options.max_startups {
            *startup_pollfd.offset(i as isize) = -(1 as libc::c_int);
            if *startup_pipes.offset(i as isize) != -(1 as libc::c_int) {
                (*pfd.offset(npfd as isize)).fd = *startup_pipes.offset(i as isize);
                (*pfd.offset(npfd as isize)).events = 0x1 as libc::c_int as libc::c_short;
                let fresh3 = npfd;
                npfd = npfd + 1;
                *startup_pollfd.offset(i as isize) = fresh3;
            }
            i += 1;
            i;
        }
        ret = ppoll(
            pfd,
            npfd as nfds_t,
            0 as *const libc::timespec,
            &mut osigset,
        );
        if ret == -(1 as libc::c_int) && *libc::__errno_location() != 4 as libc::c_int {
            crate::log::sshlog(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"server_accept_loop\0",
                ))
                .as_ptr(),
                1201 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"ppoll: %.100s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
            if *libc::__errno_location() == 22 as libc::c_int {
                cleanup_exit(1 as libc::c_int);
            }
        }
        sigprocmask(2 as libc::c_int, &mut osigset, 0 as *mut sigset_t);
        if ret == -(1 as libc::c_int) {
            continue;
        }
        let mut current_block_70: u64;
        i = 0 as libc::c_int;
        while i < options.max_startups {
            if !(*startup_pipes.offset(i as isize) == -(1 as libc::c_int)
                || *startup_pollfd.offset(i as isize) == -(1 as libc::c_int)
                || (*pfd.offset(*startup_pollfd.offset(i as isize) as isize)).revents
                    as libc::c_int
                    & (0x1 as libc::c_int | 0x10 as libc::c_int)
                    == 0)
            {
                match read(
                    *startup_pipes.offset(i as isize),
                    &mut c as *mut libc::c_char as *mut libc::c_void,
                    ::core::mem::size_of::<libc::c_char>() as libc::c_ulong,
                ) {
                    -1 => {
                        current_block_70 = 7976000509752155094;
                        match current_block_70 {
                            7976000509752155094 => {
                                if *libc::__errno_location() == 4 as libc::c_int
                                    || *libc::__errno_location() == 11 as libc::c_int
                                {
                                    current_block_70 = 6476622998065200121;
                                } else {
                                    if *libc::__errno_location() != 32 as libc::c_int {
                                        crate::log::sshlog(
                                            b"sshd.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 19],
                                                &[libc::c_char; 19],
                                            >(
                                                b"server_accept_loop\0"
                                            ))
                                            .as_ptr(),
                                            1221 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"startup pipe %d (fd=%d): read %s\0" as *const u8
                                                as *const libc::c_char,
                                            i,
                                            *startup_pipes.offset(i as isize),
                                            strerror(*libc::__errno_location()),
                                        );
                                    }
                                    current_block_70 = 9703427005353754552;
                                }
                            }
                            12185548113967751548 => {
                                if *startup_flags.offset(i as isize) != 0 {
                                    listening -= 1;
                                    listening;
                                    *startup_flags.offset(i as isize) = 0 as libc::c_int;
                                }
                                current_block_70 = 6476622998065200121;
                            }
                            _ => {}
                        }
                        match current_block_70 {
                            6476622998065200121 => {}
                            _ => {
                                close(*startup_pipes.offset(i as isize));
                                srclimit_done(*startup_pipes.offset(i as isize));
                                *startup_pipes.offset(i as isize) = -(1 as libc::c_int);
                                startups -= 1;
                                startups;
                                if *startup_flags.offset(i as isize) != 0 {
                                    listening -= 1;
                                    listening;
                                }
                            }
                        }
                    }
                    0 => {
                        current_block_70 = 9703427005353754552;
                        match current_block_70 {
                            7976000509752155094 => {
                                if *libc::__errno_location() == 4 as libc::c_int
                                    || *libc::__errno_location() == 11 as libc::c_int
                                {
                                    current_block_70 = 6476622998065200121;
                                } else {
                                    if *libc::__errno_location() != 32 as libc::c_int {
                                        crate::log::sshlog(
                                            b"sshd.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 19],
                                                &[libc::c_char; 19],
                                            >(
                                                b"server_accept_loop\0"
                                            ))
                                            .as_ptr(),
                                            1221 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"startup pipe %d (fd=%d): read %s\0" as *const u8
                                                as *const libc::c_char,
                                            i,
                                            *startup_pipes.offset(i as isize),
                                            strerror(*libc::__errno_location()),
                                        );
                                    }
                                    current_block_70 = 9703427005353754552;
                                }
                            }
                            12185548113967751548 => {
                                if *startup_flags.offset(i as isize) != 0 {
                                    listening -= 1;
                                    listening;
                                    *startup_flags.offset(i as isize) = 0 as libc::c_int;
                                }
                                current_block_70 = 6476622998065200121;
                            }
                            _ => {}
                        }
                        match current_block_70 {
                            6476622998065200121 => {}
                            _ => {
                                close(*startup_pipes.offset(i as isize));
                                srclimit_done(*startup_pipes.offset(i as isize));
                                *startup_pipes.offset(i as isize) = -(1 as libc::c_int);
                                startups -= 1;
                                startups;
                                if *startup_flags.offset(i as isize) != 0 {
                                    listening -= 1;
                                    listening;
                                }
                            }
                        }
                    }
                    1 => {
                        current_block_70 = 12185548113967751548;
                        match current_block_70 {
                            7976000509752155094 => {
                                if *libc::__errno_location() == 4 as libc::c_int
                                    || *libc::__errno_location() == 11 as libc::c_int
                                {
                                    current_block_70 = 6476622998065200121;
                                } else {
                                    if *libc::__errno_location() != 32 as libc::c_int {
                                        crate::log::sshlog(
                                            b"sshd.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 19],
                                                &[libc::c_char; 19],
                                            >(
                                                b"server_accept_loop\0"
                                            ))
                                            .as_ptr(),
                                            1221 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"startup pipe %d (fd=%d): read %s\0" as *const u8
                                                as *const libc::c_char,
                                            i,
                                            *startup_pipes.offset(i as isize),
                                            strerror(*libc::__errno_location()),
                                        );
                                    }
                                    current_block_70 = 9703427005353754552;
                                }
                            }
                            12185548113967751548 => {
                                if *startup_flags.offset(i as isize) != 0 {
                                    listening -= 1;
                                    listening;
                                    *startup_flags.offset(i as isize) = 0 as libc::c_int;
                                }
                                current_block_70 = 6476622998065200121;
                            }
                            _ => {}
                        }
                        match current_block_70 {
                            6476622998065200121 => {}
                            _ => {
                                close(*startup_pipes.offset(i as isize));
                                srclimit_done(*startup_pipes.offset(i as isize));
                                *startup_pipes.offset(i as isize) = -(1 as libc::c_int);
                                startups -= 1;
                                startups;
                                if *startup_flags.offset(i as isize) != 0 {
                                    listening -= 1;
                                    listening;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            i += 1;
            i;
        }
        i = 0 as libc::c_int;
        while i < num_listen_socks {
            if !((*pfd.offset(i as isize)).revents as libc::c_int & 0x1 as libc::c_int == 0) {
                fromlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
                *newsock = accept(
                    listen_socks[i as usize],
                    __SOCKADDR_ARG {
                        __sockaddr__: &mut from as *mut sockaddr_storage as *mut sockaddr,
                    },
                    &mut fromlen,
                );
                if *newsock == -(1 as libc::c_int) {
                    if *libc::__errno_location() != 4 as libc::c_int
                        && *libc::__errno_location() != 11 as libc::c_int
                        && *libc::__errno_location() != 103 as libc::c_int
                        && *libc::__errno_location() != 11 as libc::c_int
                    {
                        crate::log::sshlog(
                            b"sshd.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                b"server_accept_loop\0",
                            ))
                            .as_ptr(),
                            1252 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"accept: %.100s\0" as *const u8 as *const libc::c_char,
                            strerror(*libc::__errno_location()),
                        );
                    }
                    if *libc::__errno_location() == 24 as libc::c_int
                        || *libc::__errno_location() == 23 as libc::c_int
                    {
                        usleep((100 as libc::c_int * 1000 as libc::c_int) as __useconds_t);
                    }
                } else if crate::misc::unset_nonblock(*newsock) == -(1 as libc::c_int) {
                    close(*newsock);
                } else if pipe(startup_p.as_mut_ptr()) == -(1 as libc::c_int) {
                    crate::log::sshlog(
                        b"sshd.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"server_accept_loop\0",
                        ))
                        .as_ptr(),
                        1262 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"pipe(startup_p): %s\0" as *const u8 as *const libc::c_char,
                        strerror(*libc::__errno_location()),
                    );
                    close(*newsock);
                } else if drop_connection(*newsock, startups, startup_p[0 as libc::c_int as usize])
                    != 0
                {
                    close(*newsock);
                    close(startup_p[0 as libc::c_int as usize]);
                    close(startup_p[1 as libc::c_int as usize]);
                } else if rexec_flag != 0
                    && libc::socketpair(
                        1 as libc::c_int,
                        SOCK_STREAM as libc::c_int,
                        0 as libc::c_int,
                        config_s,
                    ) == -(1 as libc::c_int)
                {
                    crate::log::sshlog(
                        b"sshd.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"server_accept_loop\0",
                        ))
                        .as_ptr(),
                        1276 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"reexec libc::socketpair: %s\0" as *const u8 as *const libc::c_char,
                        strerror(*libc::__errno_location()),
                    );
                    close(*newsock);
                    close(startup_p[0 as libc::c_int as usize]);
                    close(startup_p[1 as libc::c_int as usize]);
                } else {
                    j = 0 as libc::c_int;
                    while j < options.max_startups {
                        if *startup_pipes.offset(j as isize) == -(1 as libc::c_int) {
                            *startup_pipes.offset(j as isize) =
                                startup_p[0 as libc::c_int as usize];
                            startups += 1;
                            startups;
                            *startup_flags.offset(j as isize) = 1 as libc::c_int;
                            break;
                        } else {
                            j += 1;
                            j;
                        }
                    }
                    if debug_flag != 0 {
                        crate::log::sshlog(
                            b"sshd.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                b"server_accept_loop\0",
                            ))
                            .as_ptr(),
                            1301 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"Server will not libc::fork when running in debugging mode.\0"
                                as *const u8 as *const libc::c_char,
                        );
                        close_listen_socks();
                        *sock_in = *newsock;
                        *sock_out = *newsock;
                        close(startup_p[0 as libc::c_int as usize]);
                        close(startup_p[1 as libc::c_int as usize]);
                        startup_pipe = -(1 as libc::c_int);
                        pid = libc::getpid();
                        if rexec_flag != 0 {
                            send_rexec_state(*config_s.offset(0 as libc::c_int as isize), cfg);
                            close(*config_s.offset(0 as libc::c_int as isize));
                        }
                        libc::free(pfd as *mut libc::c_void);
                        return;
                    }
                    platform_pre_fork();
                    listening += 1;
                    listening;
                    pid = libc::fork();
                    if pid == 0 as libc::c_int {
                        platform_post_fork_child();
                        startup_pipe = startup_p[1 as libc::c_int as usize];
                        close_startup_pipes();
                        close_listen_socks();
                        *sock_in = *newsock;
                        *sock_out = *newsock;
                        log_init(
                            __progname,
                            options.log_level,
                            options.log_facility,
                            log_stderr,
                        );
                        if rexec_flag != 0 {
                            close(*config_s.offset(0 as libc::c_int as isize));
                        } else {
                            atomicio(
                                ::core::mem::transmute::<
                                    Option<
                                        unsafe extern "C" fn(
                                            libc::c_int,
                                            *const libc::c_void,
                                            size_t,
                                        )
                                            -> ssize_t,
                                    >,
                                    Option<
                                        unsafe extern "C" fn(
                                            libc::c_int,
                                            *mut libc::c_void,
                                            size_t,
                                        )
                                            -> ssize_t,
                                    >,
                                >(Some(
                                    write
                                        as unsafe extern "C" fn(
                                            libc::c_int,
                                            *const libc::c_void,
                                            size_t,
                                        )
                                            -> ssize_t,
                                )),
                                startup_pipe,
                                b"\0\0" as *const u8 as *const libc::c_char as *mut libc::c_void,
                                1 as libc::c_int as size_t,
                            );
                        }
                        libc::free(pfd as *mut libc::c_void);
                        return;
                    }
                    platform_post_fork_parent(pid);
                    if pid == -(1 as libc::c_int) {
                        crate::log::sshlog(
                            b"sshd.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                b"server_accept_loop\0",
                            ))
                            .as_ptr(),
                            1363 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"libc::fork: %.100s\0" as *const u8 as *const libc::c_char,
                            strerror(*libc::__errno_location()),
                        );
                    } else {
                        crate::log::sshlog(
                            b"sshd.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                b"server_accept_loop\0",
                            ))
                            .as_ptr(),
                            1365 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"Forked child %ld.\0" as *const u8 as *const libc::c_char,
                            pid as libc::c_long,
                        );
                    }
                    close(startup_p[1 as libc::c_int as usize]);
                    if rexec_flag != 0 {
                        close(*config_s.offset(1 as libc::c_int as isize));
                        send_rexec_state(*config_s.offset(0 as libc::c_int as isize), cfg);
                        close(*config_s.offset(0 as libc::c_int as isize));
                    }
                    close(*newsock);
                    arc4random_buf(
                        rnd.as_mut_ptr() as *mut libc::c_void,
                        ::core::mem::size_of::<[u_char; 256]>() as libc::c_ulong,
                    );
                    RAND_seed(
                        rnd.as_mut_ptr() as *const libc::c_void,
                        ::core::mem::size_of::<[u_char; 256]>() as libc::c_ulong as libc::c_int,
                    );
                    if RAND_bytes(rnd.as_mut_ptr(), 1 as libc::c_int) != 1 as libc::c_int {
                        sshfatal(
                            b"sshd.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                b"server_accept_loop\0",
                            ))
                            .as_ptr(),
                            1385 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"%s: RAND_bytes failed\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                b"server_accept_loop\0",
                            ))
                            .as_ptr(),
                        );
                    }
                    explicit_bzero(
                        rnd.as_mut_ptr() as *mut libc::c_void,
                        ::core::mem::size_of::<[u_char; 256]>() as libc::c_ulong,
                    );
                }
            }
            i += 1;
            i;
        }
    }
}
unsafe extern "C" fn check_ip_options(mut ssh: *mut ssh) {
    let mut sock_in: libc::c_int = ssh_packet_get_connection_in(ssh);
    let mut from: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut opts: [u_char; 200] = [0; 200];
    let mut i: socklen_t = 0;
    let mut option_size: socklen_t =
        ::core::mem::size_of::<[u_char; 200]>() as libc::c_ulong as socklen_t;
    let mut fromlen: socklen_t =
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    let mut text: [libc::c_char; 601] = [0; 601];
    memset(
        &mut from as *mut sockaddr_storage as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong,
    );
    if getpeername(
        sock_in,
        __SOCKADDR_ARG {
            __sockaddr__: &mut from as *mut sockaddr_storage as *mut sockaddr,
        },
        &mut fromlen,
    ) == -(1 as libc::c_int)
    {
        return;
    }
    if from.ss_family as libc::c_int != 2 as libc::c_int {
        return;
    }
    if getsockopt(
        sock_in,
        IPPROTO_IP as libc::c_int,
        4 as libc::c_int,
        opts.as_mut_ptr() as *mut libc::c_void,
        &mut option_size,
    ) >= 0 as libc::c_int
        && option_size != 0 as libc::c_int as libc::c_uint
    {
        text[0 as libc::c_int as usize] = '\0' as i32 as libc::c_char;
        i = 0 as libc::c_int as socklen_t;
        while i < option_size {
            libc::snprintf(
                text.as_mut_ptr()
                    .offset(i.wrapping_mul(3 as libc::c_int as libc::c_uint) as isize),
                (::core::mem::size_of::<[libc::c_char; 601]>() as libc::c_ulong)
                    .wrapping_sub(i.wrapping_mul(3 as libc::c_int as libc::c_uint) as libc::c_ulong)
                    as usize,
                b" %2.2x\0" as *const u8 as *const libc::c_char,
                opts[i as usize] as libc::c_int,
            );
            i = i.wrapping_add(1);
            i;
        }
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"check_ip_options\0"))
                .as_ptr(),
            1428 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Connection from %.100s port %d with IP opts: %.800s\0" as *const u8
                as *const libc::c_char,
            ssh_remote_ipaddr(ssh),
            ssh_remote_port(ssh),
            text.as_mut_ptr(),
        );
    }
}
unsafe extern "C" fn set_process_rdomain(mut _ssh: *mut ssh, mut _name: *const libc::c_char) {
    sshfatal(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"set_process_rdomain\0"))
            .as_ptr(),
        1470 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_FATAL,
        0 as *const libc::c_char,
        b"Unable to set routing domain: not supported in this platform\0" as *const u8
            as *const libc::c_char,
    );
}
unsafe extern "C" fn accumulate_host_timing_secret(
    mut server_cfg: *mut sshbuf,
    mut key: *mut sshkey,
) {
    static mut ctx: *mut ssh_digest_ctx = 0 as *const ssh_digest_ctx as *mut ssh_digest_ctx;
    let mut hash: *mut u_char = 0 as *mut u_char;
    let mut len: size_t = 0;
    let mut buf: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    if ctx.is_null() && {
        ctx = ssh_digest_start(4 as libc::c_int);
        ctx.is_null()
    } {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"accumulate_host_timing_secret\0",
            ))
            .as_ptr(),
            1485 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ssh_digest_start\0" as *const u8 as *const libc::c_char,
        );
    }
    if key.is_null() {
        if ssh_digest_update(
            ctx,
            sshbuf_ptr(server_cfg) as *const libc::c_void,
            sshbuf_len(server_cfg),
        ) != 0 as libc::c_int
        {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                    b"accumulate_host_timing_secret\0",
                ))
                .as_ptr(),
                1490 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"ssh_digest_update\0" as *const u8 as *const libc::c_char,
            );
        }
        len = ssh_digest_bytes(4 as libc::c_int);
        hash = xmalloc(len) as *mut u_char;
        if ssh_digest_final(ctx, hash, len) != 0 as libc::c_int {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                    b"accumulate_host_timing_secret\0",
                ))
                .as_ptr(),
                1494 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"ssh_digest_final\0" as *const u8 as *const libc::c_char,
            );
        }
        options.timing_secret = (*(hash as *const u_char).offset(0 as libc::c_int as isize)
            as u_int64_t)
            << 56 as libc::c_int
            | (*(hash as *const u_char).offset(1 as libc::c_int as isize) as u_int64_t)
                << 48 as libc::c_int
            | (*(hash as *const u_char).offset(2 as libc::c_int as isize) as u_int64_t)
                << 40 as libc::c_int
            | (*(hash as *const u_char).offset(3 as libc::c_int as isize) as u_int64_t)
                << 32 as libc::c_int
            | (*(hash as *const u_char).offset(4 as libc::c_int as isize) as u_int64_t)
                << 24 as libc::c_int
            | (*(hash as *const u_char).offset(5 as libc::c_int as isize) as u_int64_t)
                << 16 as libc::c_int
            | (*(hash as *const u_char).offset(6 as libc::c_int as isize) as u_int64_t)
                << 8 as libc::c_int
            | *(hash as *const u_char).offset(7 as libc::c_int as isize) as u_int64_t;
        freezero(hash as *mut libc::c_void, len);
        ssh_digest_free(ctx);
        ctx = 0 as *mut ssh_digest_ctx;
        return;
    }
    buf = sshbuf_new();
    if buf.is_null() {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"accumulate_host_timing_secret\0",
            ))
            .as_ptr(),
            1502 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"could not allocate buffer\0" as *const u8 as *const libc::c_char,
        );
    }
    r = sshkey_private_serialize(key, buf);
    if r != 0 as libc::c_int {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"accumulate_host_timing_secret\0",
            ))
            .as_ptr(),
            1504 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"encode %s key\0" as *const u8 as *const libc::c_char,
            sshkey_ssh_name(key),
        );
    }
    if ssh_digest_update(ctx, sshbuf_ptr(buf) as *const libc::c_void, sshbuf_len(buf))
        != 0 as libc::c_int
    {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"accumulate_host_timing_secret\0",
            ))
            .as_ptr(),
            1506 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ssh_digest_update\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_reset(buf);
    sshbuf_free(buf);
}
unsafe extern "C" fn prepare_proctitle(
    mut ac: libc::c_int,
    mut av: *mut *mut libc::c_char,
) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < ac {
        xextendf(
            &mut ret as *mut *mut libc::c_char,
            b" \0" as *const u8 as *const libc::c_char,
            b"%s\0" as *const u8 as *const libc::c_char,
            *av.offset(i as isize),
        );
        i += 1;
        i;
    }
    return ret;
}
unsafe extern "C" fn print_config(mut ssh: *mut ssh, mut connection_info: *mut connection_info) {
    if connection_info.is_null() {
        connection_info = get_connection_info(ssh, 0 as libc::c_int, 0 as libc::c_int);
    }
    (*connection_info).test = 1 as libc::c_int;
    parse_server_match_config(&mut options, &mut includes, connection_info);
    dump_config(&mut options);
    libc::exit(0 as libc::c_int);
}
unsafe fn main_0(mut ac: libc::c_int, mut av: *mut *mut libc::c_char) -> libc::c_int {
    let mut current_block: u64;
    let mut ssh: *mut ssh = 0 as *mut ssh;
    extern "C" {
        #[link_name = "BSDoptarg"]
        static mut BSDoptarg_0: *mut libc::c_char;
    }
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    let mut r: libc::c_int = 0;
    let mut opt: libc::c_int = 0;
    let mut on: libc::c_int = 1 as libc::c_int;
    let mut do_dump_cfg: libc::c_int = 0 as libc::c_int;
    let mut already_daemon: libc::c_int = 0;
    let mut remote_port: libc::c_int = 0;
    let mut sock_in: libc::c_int = -(1 as libc::c_int);
    let mut sock_out: libc::c_int = -(1 as libc::c_int);
    let mut newsock: libc::c_int = -(1 as libc::c_int);
    let mut remote_ip: *const libc::c_char = 0 as *const libc::c_char;
    let mut rdomain: *const libc::c_char = 0 as *const libc::c_char;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut laddr: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut logfile: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut config_s: [libc::c_int; 2] = [-(1 as libc::c_int), -(1 as libc::c_int)];
    let mut i: u_int = 0;
    let mut j: u_int = 0;
    let mut ibytes: u_int64_t = 0;
    let mut obytes: u_int64_t = 0;
    let mut new_umask: mode_t = 0;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut pubkey: *mut sshkey = 0 as *mut sshkey;
    let mut keytype: libc::c_int = 0;
    let mut authctxt: *mut Authctxt = 0 as *mut Authctxt;
    let mut connection_info: *mut connection_info = 0 as *mut connection_info;
    let mut sigmask: sigset_t = sigset_t { __val: [0; 16] };
    __progname =
        crate::openbsd_compat::bsd_misc::ssh_get_progname(*av.offset(0 as libc::c_int as isize));
    sigemptyset(&mut sigmask);
    sigprocmask(2 as libc::c_int, &mut sigmask, 0 as *mut sigset_t);
    saved_argc = ac;
    rexec_argc = ac;
    saved_argv = xcalloc(
        (ac + 1 as libc::c_int) as size_t,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    i = 0 as libc::c_int as u_int;
    while (i as libc::c_int) < ac {
        let ref mut fresh4 = *saved_argv.offset(i as isize);
        *fresh4 = xstrdup(*av.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    let ref mut fresh5 = *saved_argv.offset(i as isize);
    *fresh5 = 0 as *mut libc::c_char;
    compat_init_setproctitle(ac, av);
    av = saved_argv;
    if geteuid() == 0 as libc::c_int as libc::c_uint
        && setgroups(0 as libc::c_int as size_t, 0 as *const __gid_t) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1584 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"setgroups(): %.200s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    crate::misc::sanitise_stdfd();
    initialize_server_options(&mut options);
    loop {
        opt = crate::openbsd_compat::getopt_long::BSDgetopt(
            ac,
            av,
            b"C:E:b:c:f:g:h:k:o:p:u:46DGQRTdeiqrtV\0" as *const u8 as *const libc::c_char,
        );
        if !(opt != -(1 as libc::c_int)) {
            break;
        }
        let mut current_block_66: u64;
        match opt {
            52 => {
                options.address_family = 2 as libc::c_int;
                current_block_66 = 7178192492338286402;
            }
            54 => {
                options.address_family = 10 as libc::c_int;
                current_block_66 = 7178192492338286402;
            }
            102 => {
                config_file_name = BSDoptarg;
                current_block_66 = 7178192492338286402;
            }
            99 => {
                servconf_add_hostcert(
                    b"[command-line]\0" as *const u8 as *const libc::c_char,
                    0 as libc::c_int,
                    &mut options,
                    BSDoptarg,
                );
                current_block_66 = 7178192492338286402;
            }
            100 => {
                if debug_flag == 0 as libc::c_int {
                    debug_flag = 1 as libc::c_int;
                    options.log_level = SYSLOG_LEVEL_DEBUG1;
                } else if (options.log_level as libc::c_int) < SYSLOG_LEVEL_DEBUG3 as libc::c_int {
                    options.log_level += 1;
                    options.log_level;
                }
                current_block_66 = 7178192492338286402;
            }
            68 => {
                no_daemon_flag = 1 as libc::c_int;
                current_block_66 = 7178192492338286402;
            }
            71 => {
                do_dump_cfg = 1 as libc::c_int;
                current_block_66 = 7178192492338286402;
            }
            69 => {
                logfile = BSDoptarg;
                current_block_66 = 14655262897040144319;
            }
            101 => {
                current_block_66 = 14655262897040144319;
            }
            105 => {
                inetd_flag = 1 as libc::c_int;
                current_block_66 = 7178192492338286402;
            }
            114 => {
                rexec_flag = 0 as libc::c_int;
                current_block_66 = 7178192492338286402;
            }
            82 => {
                rexeced_flag = 1 as libc::c_int;
                inetd_flag = 1 as libc::c_int;
                current_block_66 = 7178192492338286402;
            }
            81 => {
                current_block_66 = 7178192492338286402;
            }
            113 => {
                options.log_level = SYSLOG_LEVEL_QUIET;
                current_block_66 = 7178192492338286402;
            }
            98 => {
                current_block_66 = 7178192492338286402;
            }
            112 => {
                options.ports_from_cmdline = 1 as libc::c_int as u_int;
                if options.num_ports >= 256 as libc::c_int as libc::c_uint {
                    libc::fprintf(
                        stderr,
                        b"too many ports.\n\0" as *const u8 as *const libc::c_char,
                    );
                    libc::exit(1 as libc::c_int);
                }
                let fresh6 = options.num_ports;
                options.num_ports = (options.num_ports).wrapping_add(1);
                options.ports[fresh6 as usize] = crate::misc::a2port(BSDoptarg);
                if options.ports
                    [(options.num_ports).wrapping_sub(1 as libc::c_int as libc::c_uint) as usize]
                    <= 0 as libc::c_int
                {
                    libc::fprintf(
                        stderr,
                        b"Bad port number.\n\0" as *const u8 as *const libc::c_char,
                    );
                    libc::exit(1 as libc::c_int);
                }
                current_block_66 = 7178192492338286402;
            }
            103 => {
                options.login_grace_time = convtime(BSDoptarg);
                if options.login_grace_time == -(1 as libc::c_int) {
                    libc::fprintf(
                        stderr,
                        b"Invalid login grace time.\n\0" as *const u8 as *const libc::c_char,
                    );
                    libc::exit(1 as libc::c_int);
                }
                current_block_66 = 7178192492338286402;
            }
            107 => {
                current_block_66 = 7178192492338286402;
            }
            104 => {
                servconf_add_hostkey(
                    b"[command-line]\0" as *const u8 as *const libc::c_char,
                    0 as libc::c_int,
                    &mut options,
                    BSDoptarg,
                    1 as libc::c_int,
                );
                current_block_66 = 7178192492338286402;
            }
            116 => {
                test_flag = 1 as libc::c_int;
                current_block_66 = 7178192492338286402;
            }
            84 => {
                test_flag = 2 as libc::c_int;
                current_block_66 = 7178192492338286402;
            }
            67 => {
                connection_info = get_connection_info(ssh, 0 as libc::c_int, 0 as libc::c_int);
                if parse_server_match_testspec(connection_info, BSDoptarg) == -(1 as libc::c_int) {
                    libc::exit(1 as libc::c_int);
                }
                current_block_66 = 7178192492338286402;
            }
            117 => {
                utmp_len = crate::openbsd_compat::strtonum::strtonum(
                    BSDoptarg,
                    0 as libc::c_int as libc::c_longlong,
                    (64 as libc::c_int + 1 as libc::c_int + 1 as libc::c_int) as libc::c_longlong,
                    0 as *mut *const libc::c_char,
                ) as u_int;
                if utmp_len > (64 as libc::c_int + 1 as libc::c_int) as libc::c_uint {
                    libc::fprintf(
                        stderr,
                        b"Invalid utmp length.\n\0" as *const u8 as *const libc::c_char,
                    );
                    libc::exit(1 as libc::c_int);
                }
                current_block_66 = 7178192492338286402;
            }
            111 => {
                line = xstrdup(BSDoptarg);
                if process_server_config_line(
                    &mut options,
                    line,
                    b"command-line\0" as *const u8 as *const libc::c_char,
                    0 as libc::c_int,
                    0 as *mut libc::c_int,
                    0 as *mut connection_info,
                    &mut includes,
                ) != 0 as libc::c_int
                {
                    libc::exit(1 as libc::c_int);
                }
                libc::free(line as *mut libc::c_void);
                current_block_66 = 7178192492338286402;
            }
            86 => {
                libc::fprintf(
                    stderr,
                    b"%s, %s\n\0" as *const u8 as *const libc::c_char,
                    b"OpenSSH_9.3\0" as *const u8 as *const libc::c_char,
                    OpenSSL_version(0 as libc::c_int),
                );
                libc::exit(0 as libc::c_int);
            }
            _ => {
                usage();
                current_block_66 = 7178192492338286402;
            }
        }
        match current_block_66 {
            14655262897040144319 => {
                log_stderr = 1 as libc::c_int;
            }
            _ => {}
        }
    }
    if rexeced_flag != 0 || inetd_flag != 0 {
        rexec_flag = 0 as libc::c_int;
    }
    if test_flag == 0
        && do_dump_cfg == 0
        && rexec_flag != 0
        && path_absolute(*av.offset(0 as libc::c_int as isize)) == 0
    {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1710 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshd re-exec requires execution with an absolute path\0" as *const u8
                as *const libc::c_char,
        );
    }
    if rexeced_flag != 0 {
        closefrom(2 as libc::c_int + 4 as libc::c_int);
    } else {
        closefrom(2 as libc::c_int + 1 as libc::c_int);
    }
    seed_rng();
    if !logfile.is_null() {
        log_redirect_stderr_to(logfile);
    }
    log_init(
        __progname,
        (if options.log_level as libc::c_int == SYSLOG_LEVEL_NOT_SET as libc::c_int {
            SYSLOG_LEVEL_INFO as libc::c_int
        } else {
            options.log_level as libc::c_int
        }) as LogLevel,
        (if options.log_facility as libc::c_int == SYSLOG_FACILITY_NOT_SET as libc::c_int {
            SYSLOG_FACILITY_AUTH as libc::c_int
        } else {
            options.log_facility as libc::c_int
        }) as SyslogFacility,
        (log_stderr != 0 || inetd_flag == 0 || debug_flag != 0) as libc::c_int,
    );
    if !(getenv(b"KRB5CCNAME\0" as *const u8 as *const libc::c_char)).is_null() {
        unsetenv(b"KRB5CCNAME\0" as *const u8 as *const libc::c_char);
    }
    sensitive_data.have_ssh2_key = 0 as libc::c_int;
    if test_flag < 2 as libc::c_int && !connection_info.is_null() {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1747 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Config test connection parameter (-C) provided without test mode (-T)\0" as *const u8
                as *const libc::c_char,
        );
    }
    cfg = sshbuf_new();
    if cfg.is_null() {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1751 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    if rexeced_flag != 0 {
        setproctitle(
            b"%s\0" as *const u8 as *const libc::c_char,
            b"[rexeced]\0" as *const u8 as *const libc::c_char,
        );
        recv_rexec_state(2 as libc::c_int + 3 as libc::c_int, cfg);
        if debug_flag == 0 {
            startup_pipe = dup(2 as libc::c_int + 2 as libc::c_int);
            close(2 as libc::c_int + 2 as libc::c_int);
            atomicio(
                ::core::mem::transmute::<
                    Option<
                        unsafe extern "C" fn(libc::c_int, *const libc::c_void, size_t) -> ssize_t,
                    >,
                    Option<unsafe extern "C" fn(libc::c_int, *mut libc::c_void, size_t) -> ssize_t>,
                >(Some(
                    write
                        as unsafe extern "C" fn(
                            libc::c_int,
                            *const libc::c_void,
                            size_t,
                        ) -> ssize_t,
                )),
                startup_pipe,
                b"\0\0" as *const u8 as *const libc::c_char as *mut libc::c_void,
                1 as libc::c_int as size_t,
            );
        }
    } else if strcasecmp(
        config_file_name,
        b"none\0" as *const u8 as *const libc::c_char,
    ) != 0 as libc::c_int
    {
        load_server_config(config_file_name, cfg);
    }
    parse_server_config(
        &mut options,
        if rexeced_flag != 0 {
            b"rexec\0" as *const u8 as *const libc::c_char
        } else {
            config_file_name as *const libc::c_char
        },
        cfg,
        &mut includes,
        0 as *mut connection_info,
        rexeced_flag,
    );
    if !(options.moduli_file).is_null() {
        dh_set_moduli_file(options.moduli_file);
    }
    fill_default_server_options(&mut options);
    if (options.authorized_keys_command_user).is_null()
        && (!(options.authorized_keys_command).is_null()
            && strcasecmp(
                options.authorized_keys_command,
                b"none\0" as *const u8 as *const libc::c_char,
            ) != 0 as libc::c_int)
    {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1783 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"AuthorizedKeysCommand set without AuthorizedKeysCommandUser\0" as *const u8
                as *const libc::c_char,
        );
    }
    if (options.authorized_principals_command_user).is_null()
        && (!(options.authorized_principals_command).is_null()
            && strcasecmp(
                options.authorized_principals_command,
                b"none\0" as *const u8 as *const libc::c_char,
            ) != 0 as libc::c_int)
    {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1788 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"AuthorizedPrincipalsCommand set without AuthorizedPrincipalsCommandUser\0"
                as *const u8 as *const libc::c_char,
        );
    }
    if options.num_auth_methods != 0 as libc::c_int as libc::c_uint {
        i = 0 as libc::c_int as u_int;
        while i < options.num_auth_methods {
            if auth2_methods_valid(*(options.auth_methods).offset(i as isize), 1 as libc::c_int)
                == 0 as libc::c_int
            {
                break;
            }
            i = i.wrapping_add(1);
            i;
        }
        if i >= options.num_auth_methods {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1804 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"AuthenticationMethods cannot be satisfied by enabled authentication methods\0"
                    as *const u8 as *const libc::c_char,
            );
        }
    }
    if BSDoptind < ac {
        libc::fprintf(
            stderr,
            b"Extra argument %s.\n\0" as *const u8 as *const libc::c_char,
            *av.offset(BSDoptind as isize),
        );
        libc::exit(1 as libc::c_int);
    }
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
        1813 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"sshd version %s, %s\0" as *const u8 as *const libc::c_char,
        b"OpenSSH_9.3\0" as *const u8 as *const libc::c_char,
        OpenSSL_version(0 as libc::c_int),
    );
    if do_dump_cfg != 0 {
        print_config(ssh, connection_info);
    }
    privsep_chroot = (use_privsep != 0
        && (libc::getuid() == 0 as libc::c_int as libc::c_uint
            || geteuid() == 0 as libc::c_int as libc::c_uint)) as libc::c_int;
    privsep_pw = getpwnam(b"sshd\0" as *const u8 as *const libc::c_char);
    if privsep_pw.is_null() {
        if privsep_chroot != 0 || options.kerberos_authentication != 0 {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1823 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Privilege separation user %s does not exist\0" as *const u8
                    as *const libc::c_char,
                b"sshd\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        privsep_pw = pwcopy(privsep_pw);
        freezero(
            (*privsep_pw).pw_passwd as *mut libc::c_void,
            strlen((*privsep_pw).pw_passwd),
        );
        (*privsep_pw).pw_passwd = xstrdup(b"*\0" as *const u8 as *const libc::c_char);
    }
    endpwent();
    sensitive_data.host_keys = xcalloc(
        options.num_host_key_files as size_t,
        ::core::mem::size_of::<*mut sshkey>() as libc::c_ulong,
    ) as *mut *mut sshkey;
    sensitive_data.host_pubkeys = xcalloc(
        options.num_host_key_files as size_t,
        ::core::mem::size_of::<*mut sshkey>() as libc::c_ulong,
    ) as *mut *mut sshkey;
    if !(options.host_key_agent).is_null() {
        if strcmp(
            options.host_key_agent,
            b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char,
        ) != 0
        {
            setenv(
                b"SSH_AUTH_SOCK\0" as *const u8 as *const libc::c_char,
                options.host_key_agent,
                1 as libc::c_int,
            );
        }
        r = ssh_get_authentication_socket(0 as *mut libc::c_int);
        if r == 0 as libc::c_int {
            have_agent = 1 as libc::c_int;
        } else {
            crate::log::sshlog(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1845 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"Could not connect to agent \"%s\"\0" as *const u8 as *const libc::c_char,
                options.host_key_agent,
            );
        }
    }
    let mut current_block_184: u64;
    i = 0 as libc::c_int as u_int;
    while i < options.num_host_key_files {
        let mut ll: libc::c_int = if *(options.host_key_file_userprovided).offset(i as isize) != 0 {
            SYSLOG_LEVEL_ERROR as libc::c_int
        } else {
            SYSLOG_LEVEL_DEBUG1 as libc::c_int
        };
        if !(*(options.host_key_files).offset(i as isize)).is_null() {
            r = sshkey_load_private(
                *(options.host_key_files).offset(i as isize),
                b"\0" as *const u8 as *const libc::c_char,
                &mut key,
                0 as *mut *mut libc::c_char,
            );
            if r != 0 as libc::c_int && r != -(24 as libc::c_int) {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1857 as libc::c_int,
                    0 as libc::c_int,
                    ll as LogLevel,
                    ssh_err(r),
                    b"Unable to load host key \"%s\"\0" as *const u8 as *const libc::c_char,
                    *(options.host_key_files).offset(i as isize),
                );
            }
            if sshkey_is_sk(key) != 0 && (*key).sk_flags as libc::c_int & 0x1 as libc::c_int != 0 {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1861 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"host key %s requires user presence, ignoring\0" as *const u8
                        as *const libc::c_char,
                    *(options.host_key_files).offset(i as isize),
                );
                (*key).sk_flags =
                    ((*key).sk_flags as libc::c_int & !(0x1 as libc::c_int)) as uint8_t;
            }
            if r == 0 as libc::c_int && !key.is_null() && {
                r = sshkey_shield_private(key);
                r != 0 as libc::c_int
            } {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1867 as libc::c_int,
                    0 as libc::c_int,
                    ll as LogLevel,
                    ssh_err(r),
                    b"Unable to shield host key \"%s\"\0" as *const u8 as *const libc::c_char,
                    *(options.host_key_files).offset(i as isize),
                );
                sshkey_free(key);
                key = 0 as *mut sshkey;
            }
            r = sshkey_load_public(
                *(options.host_key_files).offset(i as isize),
                &mut pubkey,
                0 as *mut *mut libc::c_char,
            );
            if r != 0 as libc::c_int && r != -(24 as libc::c_int) {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1874 as libc::c_int,
                    0 as libc::c_int,
                    ll as LogLevel,
                    ssh_err(r),
                    b"Unable to load host key \"%s\"\0" as *const u8 as *const libc::c_char,
                    *(options.host_key_files).offset(i as isize),
                );
            }
            if !pubkey.is_null() && !key.is_null() {
                if sshkey_equal(pubkey, key) == 0 {
                    crate::log::sshlog(
                        b"sshd.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        1878 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Public key for %s does not match private key\0" as *const u8
                            as *const libc::c_char,
                        *(options.host_key_files).offset(i as isize),
                    );
                    sshkey_free(pubkey);
                    pubkey = 0 as *mut sshkey;
                }
            }
            if pubkey.is_null() && !key.is_null() {
                r = sshkey_from_private(key, &mut pubkey);
                if r != 0 as libc::c_int {
                    sshfatal(
                        b"sshd.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        1886 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        ssh_err(r),
                        b"Could not demote key: \"%s\"\0" as *const u8 as *const libc::c_char,
                        *(options.host_key_files).offset(i as isize),
                    );
                }
            }
            if !pubkey.is_null() && {
                r = sshkey_check_rsa_length(pubkey, options.required_rsa_size);
                r != 0 as libc::c_int
            } {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1890 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"Host key %s\0" as *const u8 as *const libc::c_char,
                    *(options.host_key_files).offset(i as isize),
                );
                sshkey_free(pubkey);
                sshkey_free(key);
            } else {
                let ref mut fresh7 = *(sensitive_data.host_keys).offset(i as isize);
                *fresh7 = key;
                let ref mut fresh8 = *(sensitive_data.host_pubkeys).offset(i as isize);
                *fresh8 = pubkey;
                if key.is_null() && !pubkey.is_null() && have_agent != 0 {
                    crate::log::sshlog(
                        b"sshd.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        1900 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"will rely on agent for hostkey %s\0" as *const u8 as *const libc::c_char,
                        *(options.host_key_files).offset(i as isize),
                    );
                    keytype = (*pubkey).type_0;
                    current_block_184 = 15893259297948756593;
                } else if !key.is_null() {
                    keytype = (*key).type_0;
                    accumulate_host_timing_secret(cfg, key);
                    current_block_184 = 15893259297948756593;
                } else {
                    crate::log::sshlog(
                        b"sshd.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        1907 as libc::c_int,
                        0 as libc::c_int,
                        ll as LogLevel,
                        0 as *const libc::c_char,
                        b"Unable to load host key: %s\0" as *const u8 as *const libc::c_char,
                        *(options.host_key_files).offset(i as isize),
                    );
                    let ref mut fresh9 = *(sensitive_data.host_keys).offset(i as isize);
                    *fresh9 = 0 as *mut sshkey;
                    let ref mut fresh10 = *(sensitive_data.host_pubkeys).offset(i as isize);
                    *fresh10 = 0 as *mut sshkey;
                    current_block_184 = 7337917895049117968;
                }
                match current_block_184 {
                    7337917895049117968 => {}
                    _ => {
                        match keytype {
                            0 | 1 | 2 | 3 | 10 | 12 | 8 => {
                                if have_agent != 0 || !key.is_null() {
                                    sensitive_data.have_ssh2_key = 1 as libc::c_int;
                                }
                            }
                            _ => {}
                        }
                        fp = sshkey_fingerprint(pubkey, options.fingerprint_hash, SSH_FP_DEFAULT);
                        if fp.is_null() {
                            sshfatal(
                                b"sshd.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(
                                    b"main\0",
                                ))
                                .as_ptr(),
                                1927 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_FATAL,
                                0 as *const libc::c_char,
                                b"sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
                            );
                        }
                        crate::log::sshlog(
                            b"sshd.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            1929 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"%s host key #%d: %s %s\0" as *const u8 as *const libc::c_char,
                            if !key.is_null() {
                                b"private\0" as *const u8 as *const libc::c_char
                            } else {
                                b"agent\0" as *const u8 as *const libc::c_char
                            },
                            i,
                            sshkey_ssh_name(pubkey),
                            fp,
                        );
                        libc::free(fp as *mut libc::c_void);
                    }
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    accumulate_host_timing_secret(cfg, 0 as *mut sshkey);
    if sensitive_data.have_ssh2_key == 0 {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            1934 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"sshd: no hostkeys available -- exiting.\0" as *const u8 as *const libc::c_char,
        );
        libc::exit(1 as libc::c_int);
    }
    sensitive_data.host_certificates = xcalloc(
        options.num_host_key_files as size_t,
        ::core::mem::size_of::<*mut sshkey>() as libc::c_ulong,
    ) as *mut *mut sshkey;
    i = 0 as libc::c_int as u_int;
    while i < options.num_host_key_files {
        let ref mut fresh11 = *(sensitive_data.host_certificates).offset(i as isize);
        *fresh11 = 0 as *mut sshkey;
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < options.num_host_cert_files {
        if !(*(options.host_cert_files).offset(i as isize)).is_null() {
            r = sshkey_load_public(
                *(options.host_cert_files).offset(i as isize),
                &mut key,
                0 as *mut *mut libc::c_char,
            );
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1953 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"Could not load host certificate \"%s\"\0" as *const u8 as *const libc::c_char,
                    *(options.host_cert_files).offset(i as isize),
                );
            } else if sshkey_is_cert(key) == 0 {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    1958 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Certificate file is not a certificate: %s\0" as *const u8
                        as *const libc::c_char,
                    *(options.host_cert_files).offset(i as isize),
                );
                sshkey_free(key);
            } else {
                j = 0 as libc::c_int as u_int;
                while j < options.num_host_key_files {
                    if sshkey_equal_public(key, *(sensitive_data.host_pubkeys).offset(j as isize))
                        != 0
                    {
                        let ref mut fresh12 =
                            *(sensitive_data.host_certificates).offset(j as isize);
                        *fresh12 = key;
                        break;
                    } else {
                        j = j.wrapping_add(1);
                        j;
                    }
                }
                if j >= options.num_host_key_files {
                    crate::log::sshlog(
                        b"sshd.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        1972 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"No matching private key for certificate: %s\0" as *const u8
                            as *const libc::c_char,
                        *(options.host_cert_files).offset(i as isize),
                    );
                    sshkey_free(key);
                } else {
                    let ref mut fresh13 = *(sensitive_data.host_certificates).offset(j as isize);
                    *fresh13 = key;
                    crate::log::sshlog(
                        b"sshd.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        1978 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"host certificate: #%u type %d %s\0" as *const u8 as *const libc::c_char,
                        j,
                        (*key).type_0,
                        sshkey_type(key),
                    );
                }
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    if privsep_chroot != 0 {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if libc::stat(b"/var/empty\0" as *const u8 as *const libc::c_char, &mut st)
            == -(1 as libc::c_int)
            || (st.st_mode & 0o170000 as libc::c_int as libc::c_uint
                == 0o40000 as libc::c_int as libc::c_uint) as libc::c_int
                == 0 as libc::c_int
        {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1987 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Missing privilege separation directory: %s\0" as *const u8 as *const libc::c_char,
                b"/var/empty\0" as *const u8 as *const libc::c_char,
            );
        }
        if st.st_uid != 0 as libc::c_int as libc::c_uint
            || st.st_mode
                & (0o200 as libc::c_int >> 3 as libc::c_int
                    | 0o200 as libc::c_int >> 3 as libc::c_int >> 3 as libc::c_int)
                    as libc::c_uint
                != 0 as libc::c_int as libc::c_uint
        {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                1997 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s must be owned by root and not group or world-writable.\0" as *const u8
                    as *const libc::c_char,
                b"/var/empty\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if test_flag > 1 as libc::c_int {
        print_config(ssh, connection_info);
    }
    if test_flag != 0 {
        libc::exit(0 as libc::c_int);
    }
    if setgroups(0 as libc::c_int as size_t, 0 as *const __gid_t) < 0 as libc::c_int {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2015 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"setgroups() failed: %.200s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    if rexec_flag != 0 {
        if rexec_argc < 0 as libc::c_int {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2019 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"rexec_argc %d < 0\0" as *const u8 as *const libc::c_char,
                rexec_argc,
            );
        }
        rexec_argv = xcalloc(
            (rexec_argc + 2 as libc::c_int) as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        ) as *mut *mut libc::c_char;
        i = 0 as libc::c_int as u_int;
        while i < rexec_argc as u_int {
            crate::log::sshlog(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2022 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"rexec_argv[%d]='%s'\0" as *const u8 as *const libc::c_char,
                i,
                *saved_argv.offset(i as isize),
            );
            let ref mut fresh14 = *rexec_argv.offset(i as isize);
            *fresh14 = *saved_argv.offset(i as isize);
            i = i.wrapping_add(1);
            i;
        }
        let ref mut fresh15 = *rexec_argv.offset(rexec_argc as isize);
        *fresh15 = b"-R\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        let ref mut fresh16 = *rexec_argv.offset((rexec_argc + 1 as libc::c_int) as isize);
        *fresh16 = 0 as *mut libc::c_char;
    }
    listener_proctitle = prepare_proctitle(ac, av);
    new_umask = libc::umask(0o77 as libc::c_int as __mode_t) | 0o22 as libc::c_int as libc::c_uint;
    libc::umask(new_umask);
    if debug_flag != 0 && (inetd_flag == 0 || rexeced_flag != 0) {
        log_stderr = 1 as libc::c_int;
    }
    log_init(
        __progname,
        options.log_level,
        options.log_facility,
        log_stderr,
    );
    i = 0 as libc::c_int as u_int;
    while i < options.num_log_verbose {
        log_verbose_add(*(options.log_verbose).offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    already_daemon = daemonized();
    if !(debug_flag != 0 || inetd_flag != 0 || no_daemon_flag != 0 || already_daemon != 0) {
        if daemon(0 as libc::c_int, 0 as libc::c_int) == -(1 as libc::c_int) {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2051 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"daemon() failed: %.200s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
        disconnect_controlling_tty();
    }
    log_init(
        __progname,
        options.log_level,
        options.log_facility,
        log_stderr,
    );
    if chdir(b"/\0" as *const u8 as *const libc::c_char) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2063 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"chdir(\"/\"): %s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    crate::misc::ssh_signal(
        13 as libc::c_int,
        ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
            1 as libc::c_int as libc::intptr_t,
        ),
    );
    if inetd_flag != 0 {
        server_accept_inetd(&mut sock_in, &mut sock_out);
    } else {
        platform_pre_listen();
        server_listen();
        crate::misc::ssh_signal(
            1 as libc::c_int,
            Some(sighup_handler as unsafe extern "C" fn(libc::c_int) -> ()),
        );
        crate::misc::ssh_signal(
            17 as libc::c_int,
            Some(main_sigchld_handler as unsafe extern "C" fn(libc::c_int) -> ()),
        );
        crate::misc::ssh_signal(
            15 as libc::c_int,
            Some(sigterm_handler as unsafe extern "C" fn(libc::c_int) -> ()),
        );
        crate::misc::ssh_signal(
            3 as libc::c_int,
            Some(sigterm_handler as unsafe extern "C" fn(libc::c_int) -> ()),
        );
        if !(options.pid_file).is_null() && debug_flag == 0 {
            let mut f: *mut libc::FILE =
                fopen(options.pid_file, b"w\0" as *const u8 as *const libc::c_char);
            if f.is_null() {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    2089 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Couldn't create pid file \"%s\": %s\0" as *const u8 as *const libc::c_char,
                    options.pid_file,
                    strerror(*libc::__errno_location()),
                );
            } else {
                libc::fprintf(
                    f,
                    b"%ld\n\0" as *const u8 as *const libc::c_char,
                    libc::getpid() as libc::c_long,
                );
                fclose(f);
            }
        }
        server_accept_loop(
            &mut sock_in,
            &mut sock_out,
            &mut newsock,
            config_s.as_mut_ptr(),
        );
    }
    setproctitle(
        b"%s\0" as *const u8 as *const libc::c_char,
        b"[accepted]\0" as *const u8 as *const libc::c_char,
    );
    if debug_flag == 0 && inetd_flag == 0 && setsid() == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2110 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"setsid: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    if rexec_flag != 0 {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2114 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"rexec start in %d out %d newsock %d pipe %d sock %d\0" as *const u8
                as *const libc::c_char,
            sock_in,
            sock_out,
            newsock,
            startup_pipe,
            config_s[0 as libc::c_int as usize],
        );
        if libc::dup2(newsock, 0 as libc::c_int) == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2116 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"libc::dup2 stdin: %s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
        if libc::dup2(0 as libc::c_int, 1 as libc::c_int) == -(1 as libc::c_int) {
            crate::log::sshlog(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2118 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"libc::dup2 stdout: %s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
        if startup_pipe == -(1 as libc::c_int) {
            close(2 as libc::c_int + 2 as libc::c_int);
        } else if startup_pipe != 2 as libc::c_int + 2 as libc::c_int {
            if libc::dup2(startup_pipe, 2 as libc::c_int + 2 as libc::c_int) == -(1 as libc::c_int)
            {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    2123 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"libc::dup2 startup_p: %s\0" as *const u8 as *const libc::c_char,
                    strerror(*libc::__errno_location()),
                );
            }
            close(startup_pipe);
            startup_pipe = 2 as libc::c_int + 2 as libc::c_int;
        }
        if libc::dup2(
            config_s[1 as libc::c_int as usize],
            2 as libc::c_int + 3 as libc::c_int,
        ) == -(1 as libc::c_int)
        {
            crate::log::sshlog(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2129 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"libc::dup2 config_s: %s\0" as *const u8 as *const libc::c_char,
                strerror(*libc::__errno_location()),
            );
        }
        close(config_s[1 as libc::c_int as usize]);
        crate::misc::ssh_signal(
            1 as libc::c_int,
            ::core::mem::transmute::<libc::intptr_t, __sighandler_t>(
                1 as libc::c_int as libc::intptr_t,
            ),
        );
        execv(
            *rexec_argv.offset(0 as libc::c_int as isize),
            rexec_argv as *const *mut libc::c_char,
        );
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2136 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"rexec of %s failed: %s\0" as *const u8 as *const libc::c_char,
            *rexec_argv.offset(0 as libc::c_int as isize),
            strerror(*libc::__errno_location()),
        );
        recv_rexec_state(2 as libc::c_int + 3 as libc::c_int, 0 as *mut sshbuf);
        log_init(
            __progname,
            options.log_level,
            options.log_facility,
            log_stderr,
        );
        close(2 as libc::c_int + 3 as libc::c_int);
        sock_in = dup(0 as libc::c_int);
        sock_out = sock_in;
        newsock = sock_out;
        if stdfd_devnull(1 as libc::c_int, 1 as libc::c_int, 0 as libc::c_int)
            == -(1 as libc::c_int)
        {
            crate::log::sshlog(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                2145 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"stdfd_devnull failed\0" as *const u8 as *const libc::c_char,
            );
        }
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2147 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"rexec cleanup in %d out %d newsock %d pipe %d sock %d\0" as *const u8
                as *const libc::c_char,
            sock_in,
            sock_out,
            newsock,
            startup_pipe,
            config_s[0 as libc::c_int as usize],
        );
    }
    fcntl(sock_out, 2 as libc::c_int, 1 as libc::c_int);
    fcntl(sock_in, 2 as libc::c_int, 1 as libc::c_int);
    crate::misc::ssh_signal(14 as libc::c_int, None);
    crate::misc::ssh_signal(1 as libc::c_int, None);
    crate::misc::ssh_signal(15 as libc::c_int, None);
    crate::misc::ssh_signal(3 as libc::c_int, None);
    crate::misc::ssh_signal(17 as libc::c_int, None);
    crate::misc::ssh_signal(2 as libc::c_int, None);
    ssh = ssh_packet_set_connection(0 as *mut ssh, sock_in, sock_out);
    if ssh.is_null() {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2167 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Unable to create connection\0" as *const u8 as *const libc::c_char,
        );
    }
    the_active_state = ssh;
    ssh_packet_set_server(ssh);
    check_ip_options(ssh);
    channel_init_channels(ssh);
    channel_set_af(ssh, options.address_family);
    process_channel_timeouts(ssh, &mut options);
    process_permitopen(ssh, &mut options);
    if options.tcp_keep_alive != 0
        && ssh_packet_connection_is_on_socket(ssh) != 0
        && setsockopt(
            sock_in,
            1 as libc::c_int,
            9 as libc::c_int,
            &mut on as *mut libc::c_int as *const libc::c_void,
            ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t,
        ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2182 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"setsockopt SO_KEEPALIVE: %.100s\0" as *const u8 as *const libc::c_char,
            strerror(*libc::__errno_location()),
        );
    }
    remote_port = ssh_remote_port(ssh);
    if remote_port < 0 as libc::c_int {
        crate::log::sshlog(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2185 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"ssh_remote_port failed\0" as *const u8 as *const libc::c_char,
        );
        cleanup_exit(255 as libc::c_int);
    }
    if !(options.routing_domain).is_null() {
        set_process_rdomain(ssh, options.routing_domain);
    }
    remote_ip = ssh_remote_ipaddr(ssh);
    rdomain = ssh_packet_rdomain_in(ssh);
    laddr = get_local_ipaddr(sock_in);
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
        2211 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_VERBOSE,
        0 as *const libc::c_char,
        b"Connection from %s port %d on %s port %d%s%s%s\0" as *const u8 as *const libc::c_char,
        remote_ip,
        remote_port,
        laddr,
        ssh_local_port(ssh),
        if rdomain.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b" rdomain \"\0" as *const u8 as *const libc::c_char
        },
        if rdomain.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            rdomain
        },
        if rdomain.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            b"\"\0" as *const u8 as *const libc::c_char
        },
    );
    libc::free(laddr as *mut libc::c_void);
    crate::misc::ssh_signal(
        14 as libc::c_int,
        Some(grace_alarm_handler as unsafe extern "C" fn(libc::c_int) -> ()),
    );
    if debug_flag == 0 {
        alarm(options.login_grace_time as libc::c_uint);
    }
    r = kex_exchange_identification(ssh, -(1 as libc::c_int), options.version_addendum);
    if r != 0 as libc::c_int {
        sshpkt_fatal(
            ssh,
            r,
            b"banner exchange\0" as *const u8 as *const libc::c_char,
        );
    }
    ssh_packet_set_nonblocking(ssh);
    authctxt = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<Authctxt>() as libc::c_ulong,
    ) as *mut Authctxt;
    (*ssh).authctxt = authctxt as *mut libc::c_void;
    (*authctxt).loginmsg = loginmsg;
    the_authctxt = authctxt;
    auth_opts = sshauthopt_new_with_keys_defaults();
    if auth_opts.is_null() {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2243 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"allocation failed\0" as *const u8 as *const libc::c_char,
        );
    }
    loginmsg = sshbuf_new();
    if loginmsg.is_null() {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            2247 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshbuf_new failed\0" as *const u8 as *const libc::c_char,
        );
    }
    auth_debug_reset();
    if use_privsep != 0 {
        if privsep_preauth(ssh) == 1 as libc::c_int {
            current_block = 5288093504656326498;
        } else {
            current_block = 16070719095729554596;
        }
    } else {
        if have_agent != 0 {
            r = ssh_get_authentication_socket(&mut auth_sock);
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    2255 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"Unable to get agent socket\0" as *const u8 as *const libc::c_char,
                );
                have_agent = 0 as libc::c_int;
            }
        }
        current_block = 16070719095729554596;
    }
    match current_block {
        16070719095729554596 => {
            do_ssh2_kex(ssh);
            do_authentication2(ssh);
            if use_privsep != 0 {
                mm_send_keystate(ssh, pmonitor);
                ssh_packet_clear_keys(ssh);
                libc::exit(0 as libc::c_int);
            }
        }
        _ => {}
    }
    alarm(0 as libc::c_int as libc::c_uint);
    crate::misc::ssh_signal(14 as libc::c_int, None);
    (*authctxt).authenticated = 1 as libc::c_int;
    if startup_pipe != -(1 as libc::c_int) {
        close(startup_pipe);
        startup_pipe = -(1 as libc::c_int);
    }
    if use_privsep != 0 {
        privsep_postauth(ssh, authctxt);
    }
    ssh_packet_set_timeout(
        ssh,
        options.client_alive_interval,
        options.client_alive_count_max,
    );
    notify_hostkeys(ssh);
    do_authenticated(ssh, authctxt);
    ssh_packet_get_bytes(ssh, &mut ibytes, &mut obytes);
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
        2327 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_VERBOSE,
        0 as *const libc::c_char,
        b"Transferred: sent %llu, received %llu bytes\0" as *const u8 as *const libc::c_char,
        obytes as libc::c_ulonglong,
        ibytes as libc::c_ulonglong,
    );
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
        2329 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_VERBOSE,
        0 as *const libc::c_char,
        b"Closing connection to %.500s port %d\0" as *const u8 as *const libc::c_char,
        remote_ip,
        remote_port,
    );
    ssh_packet_close(ssh);
    if use_privsep != 0 {
        mm_terminate();
    }
    libc::exit(0 as libc::c_int);
}
pub unsafe extern "C" fn sshd_hostkey_sign(
    mut ssh: *mut ssh,
    mut privkey: *mut sshkey,
    mut pubkey: *mut sshkey,
    mut signature: *mut *mut u_char,
    mut slenp: *mut size_t,
    mut data: *const u_char,
    mut dlen: size_t,
    mut alg: *const libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    if use_privsep != 0 {
        if !privkey.is_null() {
            if mm_sshkey_sign(
                ssh,
                privkey,
                signature,
                slenp,
                data,
                dlen,
                alg,
                options.sk_provider,
                0 as *const libc::c_char,
                (*ssh).compat as u_int,
            ) < 0 as libc::c_int
            {
                sshfatal(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"sshd_hostkey_sign\0",
                    ))
                    .as_ptr(),
                    2360 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"privkey sign failed\0" as *const u8 as *const libc::c_char,
                );
            }
        } else if mm_sshkey_sign(
            ssh,
            pubkey,
            signature,
            slenp,
            data,
            dlen,
            alg,
            options.sk_provider,
            0 as *const libc::c_char,
            (*ssh).compat as u_int,
        ) < 0 as libc::c_int
        {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"sshd_hostkey_sign\0"))
                    .as_ptr(),
                2365 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"pubkey sign failed\0" as *const u8 as *const libc::c_char,
            );
        }
    } else if !privkey.is_null() {
        if sshkey_sign(
            privkey,
            signature,
            slenp,
            data,
            dlen,
            alg,
            options.sk_provider,
            0 as *const libc::c_char,
            (*ssh).compat as u_int,
        ) < 0 as libc::c_int
        {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"sshd_hostkey_sign\0"))
                    .as_ptr(),
                2371 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"privkey sign failed\0" as *const u8 as *const libc::c_char,
            );
        }
    } else {
        r = ssh_agent_sign(
            auth_sock,
            pubkey,
            signature,
            slenp,
            data,
            dlen,
            alg,
            (*ssh).compat as u_int,
        );
        if r != 0 as libc::c_int {
            sshfatal(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"sshd_hostkey_sign\0"))
                    .as_ptr(),
                2376 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"agent sign failed\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn do_ssh2_kex(mut ssh: *mut ssh) {
    let mut hkalgs: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut myproposal: [*mut libc::c_char; 10] = [0 as *mut libc::c_char; 10];
    let mut compression: *const libc::c_char = 0 as *const libc::c_char;
    let mut kex: *mut kex = 0 as *mut kex;
    let mut r: libc::c_int = 0;
    if options.rekey_limit != 0 || options.rekey_interval != 0 {
        ssh_packet_set_rekey_limits(
            ssh,
            options.rekey_limit as u_int64_t,
            options.rekey_interval as u_int32_t,
        );
    }
    if options.compression == 0 as libc::c_int {
        compression = b"none\0" as *const u8 as *const libc::c_char;
    }
    hkalgs = list_hostkey_types();
    kex_proposal_populate_entries(
        ssh,
        myproposal.as_mut_ptr(),
        options.kex_algorithms,
        options.ciphers,
        options.macs,
        compression,
        hkalgs,
    );
    libc::free(hkalgs as *mut libc::c_void);
    r = kex_setup(ssh, myproposal.as_mut_ptr());
    if r != 0 as libc::c_int {
        sshfatal(
            b"sshd.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_ssh2_kex\0")).as_ptr(),
            2407 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"kex_setup\0" as *const u8 as *const libc::c_char,
        );
    }
    kex = (*ssh).kex;
    (*kex).kex[KEX_DH_GRP1_SHA1 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_DH_GRP14_SHA1 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_DH_GRP14_SHA256 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_DH_GRP16_SHA512 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_DH_GRP18_SHA512 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_DH_GEX_SHA1 as libc::c_int as usize] =
        Some(kexgex_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_DH_GEX_SHA256 as libc::c_int as usize] =
        Some(kexgex_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_ECDH_SHA2 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_C25519_SHA256 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).kex[KEX_KEM_SNTRUP761X25519_SHA512 as libc::c_int as usize] =
        Some(kex_gen_server as unsafe extern "C" fn(*mut ssh) -> libc::c_int);
    (*kex).load_host_public_key = Some(
        get_hostkey_public_by_type
            as unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut sshkey,
    );
    (*kex).load_host_private_key = Some(
        get_hostkey_private_by_type
            as unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut sshkey,
    );
    (*kex).host_key_index = Some(
        get_hostkey_index
            as unsafe extern "C" fn(*mut sshkey, libc::c_int, *mut ssh) -> libc::c_int,
    );
    (*kex).sign = Some(
        sshd_hostkey_sign
            as unsafe extern "C" fn(
                *mut ssh,
                *mut sshkey,
                *mut sshkey,
                *mut *mut u_char,
                *mut size_t,
                *const u_char,
                size_t,
                *const libc::c_char,
            ) -> libc::c_int,
    );
    ssh_dispatch_run_fatal(
        ssh,
        DISPATCH_BLOCK as libc::c_int,
        &mut (*kex).done as *mut sig_atomic_t as *mut sig_atomic_t,
    );
    kex_proposal_free_entries(myproposal.as_mut_ptr());
    crate::log::sshlog(
        b"sshd.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"do_ssh2_kex\0")).as_ptr(),
        2439 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"KEX done\0" as *const u8 as *const libc::c_char,
    );
}
pub unsafe extern "C" fn cleanup_exit(mut i: libc::c_int) -> ! {
    if !the_active_state.is_null() && !the_authctxt.is_null() {
        do_cleanup(the_active_state, the_authctxt);
        if use_privsep != 0
            && privsep_is_preauth != 0
            && !pmonitor.is_null()
            && (*pmonitor).m_pid > 1 as libc::c_int
        {
            crate::log::sshlog(
                b"sshd.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"cleanup_exit\0"))
                    .as_ptr(),
                2450 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Killing privsep child %d\0" as *const u8 as *const libc::c_char,
                (*pmonitor).m_pid,
            );
            if kill((*pmonitor).m_pid, 9 as libc::c_int) != 0 as libc::c_int
                && *libc::__errno_location() != 3 as libc::c_int
            {
                crate::log::sshlog(
                    b"sshd.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"cleanup_exit\0"))
                        .as_ptr(),
                    2454 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"kill(%d): %s\0" as *const u8 as *const libc::c_char,
                    (*pmonitor).m_pid,
                    strerror(*libc::__errno_location()),
                );
            }
        }
    }
    libc::_exit(i);
}
pub fn main() {
    let mut args: Vec<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::core::ptr::null_mut());
    unsafe {
        ::std::process::exit(main_0(
            (args.len() - 1) as libc::c_int,
            args.as_mut_ptr() as *mut *mut libc::c_char,
        ) as i32)
    }
}
unsafe extern "C" fn run_static_initializers() {
    includes = {
        let mut init = include_list {
            tqh_first: 0 as *mut include_item,
            tqh_last: &mut includes.tqh_first,
        };
        init
    };
}
#[used]
#[cfg_attr(target_os = "linux", link_section = ".init_array")]
#[cfg_attr(target_os = "windows", link_section = ".CRT$XIB")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
static INIT_ARRAY: [unsafe extern "C" fn(); 1] = [run_static_initializers];
