use ::libc;
use libc::close;
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
    pub type ssh_channels;

    pub type ec_key_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_group_st;
    pub type dh_st;
    pub type umac_ctx;
    pub type ssh_hmac_ctx;
    pub type sshcipher;
    pub type internal_state;
    pub type sshcipher_ctx;
    pub type bignum_st;
    pub type ec_point_st;
    fn getpeername(__fd: libc::c_int, __addr: __SOCKADDR_ARG, __len: *mut socklen_t)
        -> libc::c_int;

    fn read(__fd: libc::c_int, __buf: *mut libc::c_void, __nbytes: size_t) -> ssize_t;
    fn write(__fd: libc::c_int, __buf: *const libc::c_void, __n: size_t) -> ssize_t;

    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn vasprintf(
        __ptr: *mut *mut libc::c_char,
        __f: *const libc::c_char,
        __arg: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn ppoll(
        __fds: *mut pollfd,
        __nfds: nfds_t,
        __timeout: *const libc::timespec,
        __ss: *const __sigset_t,
    ) -> libc::c_int;
    fn arc4random() -> uint32_t;
    fn arc4random_buf(_: *mut libc::c_void, _: size_t);

    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn deflate(strm: z_streamp, flush: libc::c_int) -> libc::c_int;
    fn deflateEnd(strm: z_streamp) -> libc::c_int;
    fn inflate(strm: z_streamp, flush: libc::c_int) -> libc::c_int;
    fn inflateEnd(strm: z_streamp) -> libc::c_int;
    fn deflateInit_(
        strm: z_streamp,
        level: libc::c_int,
        version: *const libc::c_char,
        stream_size: libc::c_int,
    ) -> libc::c_int;
    fn inflateInit_(
        strm: z_streamp,
        version: *const libc::c_char,
        stream_size: libc::c_int,
    ) -> libc::c_int;

    fn cipher_by_name(_: *const libc::c_char) -> *const sshcipher;
    fn cipher_warning_message(_: *const sshcipher_ctx) -> *const libc::c_char;
    fn cipher_init(
        _: *mut *mut sshcipher_ctx,
        _: *const sshcipher,
        _: *const u_char,
        _: u_int,
        _: *const u_char,
        _: u_int,
        _: libc::c_int,
    ) -> libc::c_int;
    fn cipher_crypt(
        _: *mut sshcipher_ctx,
        _: u_int,
        _: *mut u_char,
        _: *const u_char,
        _: u_int,
        _: u_int,
        _: u_int,
    ) -> libc::c_int;
    fn cipher_get_length(
        _: *mut sshcipher_ctx,
        _: *mut u_int,
        _: u_int,
        _: *const u_char,
        _: u_int,
    ) -> libc::c_int;
    fn cipher_free(_: *mut sshcipher_ctx);
    fn cipher_authlen(_: *const sshcipher) -> u_int;
    fn cipher_is_cbc(_: *const sshcipher) -> u_int;
    fn cipher_ctx_is_plaintext(_: *mut sshcipher_ctx) -> u_int;
    fn cipher_get_keyiv(_: *mut sshcipher_ctx, _: *mut u_char, _: size_t) -> libc::c_int;
    fn kex_new() -> *mut kex;
    fn kex_free_newkeys(_: *mut newkeys);
    fn kex_free(_: *mut kex);
    fn kex_start_rekex(_: *mut ssh) -> libc::c_int;
    fn mac_setup(_: *mut sshmac, _: *mut libc::c_char) -> libc::c_int;
    fn mac_init(_: *mut sshmac) -> libc::c_int;
    fn mac_compute(
        _: *mut sshmac,
        _: u_int32_t,
        _: *const u_char,
        _: libc::c_int,
        _: *mut u_char,
        _: size_t,
    ) -> libc::c_int;
    fn mac_check(
        _: *mut sshmac,
        _: u_int32_t,
        _: *const u_char,
        _: size_t,
        _: *const u_char,
        _: size_t,
    ) -> libc::c_int;
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn cleanup_exit(_: libc::c_int) -> !;

    fn sshlogdie(
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
    fn get_peer_ipaddr(_: libc::c_int) -> *mut libc::c_char;
    fn get_peer_port(_: libc::c_int) -> libc::c_int;
    fn get_local_ipaddr(_: libc::c_int) -> *mut libc::c_char;
    fn get_local_port(_: libc::c_int) -> libc::c_int;

    fn set_nodelay(_: libc::c_int);
    fn get_rdomain(_: libc::c_int) -> *mut libc::c_char;
    fn get_sock_af(_: libc::c_int) -> libc::c_int;
    fn set_sock_tos(_: libc::c_int, _: libc::c_int);
    fn ms_subtract_diff(_: *mut libc::timeval, _: *mut libc::c_int);
    fn ms_to_timespec(_: *mut libc::timespec, _: libc::c_int);
    fn monotime_tv(_: *mut libc::timeval);
    fn monotime() -> time_t;

    fn sshbuf_froms(
        buf: *mut crate::sshbuf::sshbuf,
        bufp: *mut *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;

    fn sshbuf_ptr(buf: *const crate::sshbuf::sshbuf) -> *const u_char;
    fn sshbuf_mutable_ptr(buf: *const crate::sshbuf::sshbuf) -> *mut u_char;
    fn sshbuf_reserve(
        buf: *mut crate::sshbuf::sshbuf,
        len: size_t,
        dpp: *mut *mut u_char,
    ) -> libc::c_int;
    fn sshbuf_consume(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_consume_end(buf: *mut crate::sshbuf::sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_get(
        buf: *mut crate::sshbuf::sshbuf,
        v: *mut libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_put(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_putb(buf: *mut crate::sshbuf::sshbuf, v: *const crate::sshbuf::sshbuf)
        -> libc::c_int;

    fn sshbuf_get_string(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *mut crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_put_string(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut crate::sshbuf::sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_stringb(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const crate::sshbuf::sshbuf,
    ) -> libc::c_int;
    fn sshbuf_get_string_direct(
        buf: *mut crate::sshbuf::sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_peek_string_direct(
        buf: *const crate::sshbuf::sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_get_bignum2(buf: *mut crate::sshbuf::sshbuf, valp: *mut *mut BIGNUM) -> libc::c_int;
    fn sshbuf_put_bignum2(buf: *mut crate::sshbuf::sshbuf, v: *const BIGNUM) -> libc::c_int;
    fn sshbuf_get_ec(
        buf: *mut crate::sshbuf::sshbuf,
        v: *mut EC_POINT,
        g: *const EC_GROUP,
    ) -> libc::c_int;
    fn sshbuf_put_ec(
        buf: *mut crate::sshbuf::sshbuf,
        v: *const EC_POINT,
        g: *const EC_GROUP,
    ) -> libc::c_int;
    fn sshbuf_read(
        _: libc::c_int,
        _: *mut crate::sshbuf::sshbuf,
        _: size_t,
        _: *mut size_t,
    ) -> libc::c_int;
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
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __time_t = libc::c_long;
pub type __suseconds_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_int = __u_int;
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
pub type sig_atomic_t = __sig_atomic_t;
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
pub struct session_state {
    pub connection_in: libc::c_int,
    pub connection_out: libc::c_int,
    pub remote_protocol_flags: u_int,
    pub receive_context: *mut sshcipher_ctx,
    pub send_context: *mut sshcipher_ctx,
    pub input: *mut crate::sshbuf::sshbuf,
    pub output: *mut crate::sshbuf::sshbuf,
    pub outgoing_packet: *mut crate::sshbuf::sshbuf,
    pub incoming_packet: *mut crate::sshbuf::sshbuf,
    pub compression_buffer: *mut crate::sshbuf::sshbuf,
    pub compression_in_stream: z_stream,
    pub compression_out_stream: z_stream,
    pub compression_in_started: libc::c_int,
    pub compression_out_started: libc::c_int,
    pub compression_in_failures: libc::c_int,
    pub compression_out_failures: libc::c_int,
    pub max_packet_size: u_int,
    pub initialized: libc::c_int,
    pub interactive_mode: libc::c_int,
    pub server_side: libc::c_int,
    pub after_authentication: libc::c_int,
    pub keep_alive_timeouts: libc::c_int,
    pub packet_timeout_ms: libc::c_int,
    pub newkeys: [*mut newkeys; 2],
    pub p_read: packet_state,
    pub p_send: packet_state,
    pub max_blocks_in: u_int64_t,
    pub max_blocks_out: u_int64_t,
    pub rekey_limit: u_int64_t,
    pub rekey_interval: u_int32_t,
    pub rekey_time: time_t,
    pub extra_pad: u_char,
    pub packet_discard: u_int,
    pub packet_discard_mac_already: size_t,
    pub packet_discard_mac: *mut sshmac,
    pub packlen: u_int,
    pub rekeying: libc::c_int,
    pub mux: libc::c_int,
    pub set_interactive_called: libc::c_int,
    pub set_maxsize_called: libc::c_int,
    pub cipher_warning_done: libc::c_int,
    pub hook_in: Option<ssh_packet_hook_fn>,
    pub hook_in_ctx: *mut libc::c_void,
    pub outgoing: C2RustUnnamed_3,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_3 {
    pub tqh_first: *mut packet,
    pub tqh_last: *mut *mut packet,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct packet {
    pub next: C2RustUnnamed_4,
    pub type_0: u_char,
    pub payload: *mut crate::sshbuf::sshbuf,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_4 {
    pub tqe_next: *mut packet,
    pub tqe_prev: *mut *mut packet,
}
pub type ssh_packet_hook_fn = unsafe extern "C" fn(
    *mut ssh,
    *mut crate::sshbuf::sshbuf,
    *mut u_char,
    *mut libc::c_void,
) -> libc::c_int;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct packet_state {
    pub seqnr: u_int32_t,
    pub packets: u_int32_t,
    pub blocks: u_int64_t,
    pub bytes: u_int64_t,
}
pub type z_stream = z_stream_s;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct z_stream_s {
    pub next_in: *mut Bytef,
    pub avail_in: uInt,
    pub total_in: uLong,
    pub next_out: *mut Bytef,
    pub avail_out: uInt,
    pub total_out: uLong,
    pub msg: *mut libc::c_char,
    pub state: *mut internal_state,
    pub zalloc: alloc_func,
    pub zfree: free_func,
    pub opaque: voidpf,
    pub data_type: libc::c_int,
    pub adler: uLong,
    pub reserved: uLong,
}
pub type uLong = libc::c_ulong;
pub type voidpf = *mut libc::c_void;
pub type free_func = Option<unsafe extern "C" fn(voidpf, voidpf) -> ()>;
pub type alloc_func = Option<unsafe extern "C" fn(voidpf, uInt, uInt) -> voidpf>;
pub type uInt = libc::c_uint;
pub type Bytef = Byte;
pub type Byte = libc::c_uchar;
pub type BIGNUM = bignum_st;
pub type EC_POINT = ec_point_st;
pub type z_streamp = *mut z_stream;
pub type kex_modes = libc::c_uint;
pub const MODE_MAX: kex_modes = 2;
pub const MODE_OUT: kex_modes = 1;
pub const MODE_IN: kex_modes = 0;
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
pub unsafe extern "C" fn ssh_alloc_session_state() -> *mut ssh {
    let mut ssh: *mut ssh = 0 as *mut ssh;
    let mut state: *mut session_state = 0 as *mut session_state;
    ssh = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<ssh>() as libc::c_ulong,
    ) as *mut ssh;
    if ssh.is_null()
        || {
            state = calloc(
                1 as libc::c_int as libc::c_ulong,
                ::core::mem::size_of::<session_state>() as libc::c_ulong,
            ) as *mut session_state;
            state.is_null()
        }
        || {
            (*ssh).kex = kex_new();
            ((*ssh).kex).is_null()
        }
        || {
            (*state).input = crate::sshbuf::sshbuf_new();
            ((*state).input).is_null()
        }
        || {
            (*state).output = crate::sshbuf::sshbuf_new();
            ((*state).output).is_null()
        }
        || {
            (*state).outgoing_packet = crate::sshbuf::sshbuf_new();
            ((*state).outgoing_packet).is_null()
        }
        || {
            (*state).incoming_packet = crate::sshbuf::sshbuf_new();
            ((*state).incoming_packet).is_null()
        }
    {
        if !ssh.is_null() {
            kex_free((*ssh).kex);
            libc::free(ssh as *mut libc::c_void);
        }
        if !state.is_null() {
            crate::sshbuf::sshbuf_free((*state).input);
            crate::sshbuf::sshbuf_free((*state).output);
            crate::sshbuf::sshbuf_free((*state).incoming_packet);
            crate::sshbuf::sshbuf_free((*state).outgoing_packet);
            libc::free(state as *mut libc::c_void);
        }
        return 0 as *mut ssh;
    } else {
        (*state).outgoing.tqh_first = 0 as *mut packet;
        (*state).outgoing.tqh_last = &mut (*state).outgoing.tqh_first;
        (*ssh).private_keys.tqh_first = 0 as *mut key_entry;
        (*ssh).private_keys.tqh_last = &mut (*ssh).private_keys.tqh_first;
        (*ssh).public_keys.tqh_first = 0 as *mut key_entry;
        (*ssh).public_keys.tqh_last = &mut (*ssh).public_keys.tqh_first;
        (*state).connection_in = -(1 as libc::c_int);
        (*state).connection_out = -(1 as libc::c_int);
        (*state).max_packet_size = 32768 as libc::c_int as u_int;
        (*state).packet_timeout_ms = -(1 as libc::c_int);
        (*state).p_read.packets = 0 as libc::c_int as u_int32_t;
        (*state).p_send.packets = (*state).p_read.packets;
        (*state).initialized = 1 as libc::c_int;
        (*state).rekeying = 1 as libc::c_int;
        (*ssh).state = state;
        return ssh;
    };
}
pub unsafe extern "C" fn ssh_packet_set_input_hook(
    mut ssh: *mut ssh,
    mut hook: Option<ssh_packet_hook_fn>,
    mut ctx: *mut libc::c_void,
) {
    (*(*ssh).state).hook_in = hook;
    (*(*ssh).state).hook_in_ctx = ctx;
}
pub unsafe extern "C" fn ssh_packet_is_rekeying(mut ssh: *mut ssh) -> libc::c_int {
    return ((*(*ssh).state).rekeying != 0
        || !((*ssh).kex).is_null() && (*(*ssh).kex).done == 0 as libc::c_int)
        as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_set_connection(
    mut ssh: *mut ssh,
    mut fd_in: libc::c_int,
    mut fd_out: libc::c_int,
) -> *mut ssh {
    let mut state: *mut session_state = 0 as *mut session_state;
    let mut none: *const sshcipher = cipher_by_name(b"none\0" as *const u8 as *const libc::c_char);
    let mut r: libc::c_int = 0;
    if none.is_null() {
        crate::log::sshlog(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"ssh_packet_set_connection\0",
            ))
            .as_ptr(),
            300 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"cannot load cipher 'none'\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut ssh;
    }
    if ssh.is_null() {
        ssh = ssh_alloc_session_state();
    }
    if ssh.is_null() {
        crate::log::sshlog(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"ssh_packet_set_connection\0",
            ))
            .as_ptr(),
            306 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"could not allocate state\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut ssh;
    }
    state = (*ssh).state;
    (*state).connection_in = fd_in;
    (*state).connection_out = fd_out;
    r = cipher_init(
        &mut (*state).send_context,
        none,
        b"\0" as *const u8 as *const libc::c_char as *const u_char,
        0 as libc::c_int as u_int,
        0 as *const u_char,
        0 as libc::c_int as u_int,
        1 as libc::c_int,
    );
    if r != 0 as libc::c_int || {
        r = cipher_init(
            &mut (*state).receive_context,
            none,
            b"\0" as *const u8 as *const libc::c_char as *const u_char,
            0 as libc::c_int as u_int,
            0 as *const u_char,
            0 as libc::c_int as u_int,
            0 as libc::c_int,
        );
        r != 0 as libc::c_int
    } {
        crate::log::sshlog(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"ssh_packet_set_connection\0",
            ))
            .as_ptr(),
            316 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"cipher_init failed\0" as *const u8 as *const libc::c_char,
        );
        libc::free(ssh as *mut libc::c_void);
        return 0 as *mut ssh;
    }
    (*state).newkeys[MODE_OUT as libc::c_int as usize] = 0 as *mut newkeys;
    (*state).newkeys[MODE_IN as libc::c_int as usize] =
        (*state).newkeys[MODE_OUT as libc::c_int as usize];
    ssh_remote_ipaddr(ssh);
    return ssh;
}
pub unsafe extern "C" fn ssh_packet_set_timeout(
    mut ssh: *mut ssh,
    mut timeout: libc::c_int,
    mut count: libc::c_int,
) {
    let mut state: *mut session_state = (*ssh).state;
    if timeout <= 0 as libc::c_int || count <= 0 as libc::c_int {
        (*state).packet_timeout_ms = -(1 as libc::c_int);
        return;
    }
    if 2147483647 as libc::c_int / 1000 as libc::c_int / count < timeout {
        (*state).packet_timeout_ms = 2147483647 as libc::c_int;
    } else {
        (*state).packet_timeout_ms = timeout * count * 1000 as libc::c_int;
    };
}
pub unsafe extern "C" fn ssh_packet_set_mux(mut ssh: *mut ssh) {
    (*(*ssh).state).mux = 1 as libc::c_int;
    (*(*ssh).state).rekeying = 0 as libc::c_int;
    kex_free((*ssh).kex);
    (*ssh).kex = 0 as *mut kex;
}
pub unsafe extern "C" fn ssh_packet_get_mux(mut ssh: *mut ssh) -> libc::c_int {
    return (*(*ssh).state).mux;
}
pub unsafe extern "C" fn ssh_packet_set_log_preamble(
    mut ssh: *mut ssh,
    mut fmt: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut args_0: ::core::ffi::VaListImpl;
    let mut r: libc::c_int = 0;
    libc::free((*ssh).log_preamble as *mut libc::c_void);
    if fmt.is_null() {
        (*ssh).log_preamble = 0 as *mut libc::c_char;
    } else {
        args_0 = args.clone();
        r = vasprintf(&mut (*ssh).log_preamble, fmt, args_0.as_va_list());
        if r < 0 as libc::c_int || ((*ssh).log_preamble).is_null() {
            return -(2 as libc::c_int);
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_stop_discard(mut ssh: *mut ssh) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut r: libc::c_int = 0;
    if !((*state).packet_discard_mac).is_null() {
        let mut buf: [libc::c_char; 1024] = [0; 1024];
        let mut dlen: size_t = (256 as libc::c_int * 1024 as libc::c_int) as size_t;
        if dlen > (*state).packet_discard_mac_already {
            dlen = (dlen as libc::c_ulong).wrapping_sub((*state).packet_discard_mac_already)
                as size_t as size_t;
        }
        memset(
            buf.as_mut_ptr() as *mut libc::c_void,
            'a' as i32,
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        );
        while crate::sshbuf::sshbuf_len((*state).incoming_packet) < dlen {
            r = sshbuf_put(
                (*state).incoming_packet,
                buf.as_mut_ptr() as *const libc::c_void,
                ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
            );
            if r != 0 as libc::c_int {
                return r;
            }
        }
        mac_compute(
            (*state).packet_discard_mac,
            (*state).p_read.seqnr,
            sshbuf_ptr((*state).incoming_packet),
            dlen as libc::c_int,
            0 as *mut u_char,
            0 as libc::c_int as size_t,
        );
    }
    crate::log::sshlog(
        b"packet.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"ssh_packet_stop_discard\0"))
            .as_ptr(),
        401 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"Finished discarding for %.200s port %d\0" as *const u8 as *const libc::c_char,
        ssh_remote_ipaddr(ssh),
        ssh_remote_port(ssh),
    );
    return -(30 as libc::c_int);
}
unsafe extern "C" fn ssh_packet_start_discard(
    mut ssh: *mut ssh,
    mut enc: *mut sshenc,
    mut mac: *mut sshmac,
    mut mac_already: size_t,
    mut discard: u_int,
) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut r: libc::c_int = 0;
    if enc.is_null() || cipher_is_cbc((*enc).cipher) == 0 || !mac.is_null() && (*mac).etm != 0 {
        r = sshpkt_disconnect(ssh, b"Packet corrupt\0" as *const u8 as *const libc::c_char);
        if r != 0 as libc::c_int {
            return r;
        }
        return -(30 as libc::c_int);
    }
    if !mac.is_null() && (*mac).enabled != 0 {
        (*state).packet_discard_mac = mac;
        (*state).packet_discard_mac_already = mac_already;
    }
    if crate::sshbuf::sshbuf_len((*state).input) >= discard as libc::c_ulong {
        return ssh_packet_stop_discard(ssh);
    }
    (*state).packet_discard =
        (discard as libc::c_ulong).wrapping_sub(crate::sshbuf::sshbuf_len((*state).input)) as u_int;
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_connection_is_on_socket(mut ssh: *mut ssh) -> libc::c_int {
    let mut state: *mut session_state = 0 as *mut session_state;
    let mut from: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut to: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut fromlen: socklen_t = 0;
    let mut tolen: socklen_t = 0;
    if ssh.is_null() || ((*ssh).state).is_null() {
        return 0 as libc::c_int;
    }
    state = (*ssh).state;
    if (*state).connection_in == -(1 as libc::c_int)
        || (*state).connection_out == -(1 as libc::c_int)
    {
        return 0 as libc::c_int;
    }
    if (*state).connection_in == (*state).connection_out {
        return 1 as libc::c_int;
    }
    fromlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    memset(
        &mut from as *mut sockaddr_storage as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong,
    );
    if getpeername(
        (*state).connection_in,
        __SOCKADDR_ARG {
            __sockaddr__: &mut from as *mut sockaddr_storage as *mut sockaddr,
        },
        &mut fromlen,
    ) == -(1 as libc::c_int)
    {
        return 0 as libc::c_int;
    }
    tolen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
    memset(
        &mut to as *mut sockaddr_storage as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong,
    );
    if getpeername(
        (*state).connection_out,
        __SOCKADDR_ARG {
            __sockaddr__: &mut to as *mut sockaddr_storage as *mut sockaddr,
        },
        &mut tolen,
    ) == -(1 as libc::c_int)
    {
        return 0 as libc::c_int;
    }
    if fromlen != tolen
        || memcmp(
            &mut from as *mut sockaddr_storage as *const libc::c_void,
            &mut to as *mut sockaddr_storage as *const libc::c_void,
            fromlen as libc::c_ulong,
        ) != 0 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    if from.ss_family as libc::c_int != 2 as libc::c_int
        && from.ss_family as libc::c_int != 10 as libc::c_int
    {
        return 0 as libc::c_int;
    }
    return 1 as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_get_bytes(
    mut ssh: *mut ssh,
    mut ibytes: *mut u_int64_t,
    mut obytes: *mut u_int64_t,
) {
    if !ibytes.is_null() {
        *ibytes = (*(*ssh).state).p_read.bytes;
    }
    if !obytes.is_null() {
        *obytes = (*(*ssh).state).p_send.bytes;
    }
}
pub unsafe extern "C" fn ssh_packet_connection_af(mut ssh: *mut ssh) -> libc::c_int {
    return get_sock_af((*(*ssh).state).connection_out);
}
pub unsafe extern "C" fn ssh_packet_set_nonblocking(mut ssh: *mut ssh) {
    crate::misc::set_nonblock((*(*ssh).state).connection_in);
    if (*(*ssh).state).connection_out != (*(*ssh).state).connection_in {
        crate::misc::set_nonblock((*(*ssh).state).connection_out);
    }
}
pub unsafe extern "C" fn ssh_packet_get_connection_in(mut ssh: *mut ssh) -> libc::c_int {
    return (*(*ssh).state).connection_in;
}
pub unsafe extern "C" fn ssh_packet_get_connection_out(mut ssh: *mut ssh) -> libc::c_int {
    return (*(*ssh).state).connection_out;
}
pub unsafe extern "C" fn ssh_remote_ipaddr(mut ssh: *mut ssh) -> *const libc::c_char {
    let mut sock: libc::c_int = 0;
    if ((*ssh).remote_ipaddr).is_null() {
        if ssh_packet_connection_is_on_socket(ssh) != 0 {
            sock = (*(*ssh).state).connection_in;
            (*ssh).remote_ipaddr = get_peer_ipaddr(sock);
            (*ssh).remote_port = get_peer_port(sock);
            (*ssh).local_ipaddr = get_local_ipaddr(sock);
            (*ssh).local_port = get_local_port(sock);
        } else {
            (*ssh).remote_ipaddr =
                crate::xmalloc::xstrdup(b"UNKNOWN\0" as *const u8 as *const libc::c_char);
            (*ssh).remote_port = 65535 as libc::c_int;
            (*ssh).local_ipaddr =
                crate::xmalloc::xstrdup(b"UNKNOWN\0" as *const u8 as *const libc::c_char);
            (*ssh).local_port = 65535 as libc::c_int;
        }
    }
    return (*ssh).remote_ipaddr;
}
pub unsafe extern "C" fn ssh_remote_port(mut ssh: *mut ssh) -> libc::c_int {
    ssh_remote_ipaddr(ssh);
    return (*ssh).remote_port;
}
pub unsafe extern "C" fn ssh_local_ipaddr(mut ssh: *mut ssh) -> *const libc::c_char {
    ssh_remote_ipaddr(ssh);
    return (*ssh).local_ipaddr;
}
pub unsafe extern "C" fn ssh_local_port(mut ssh: *mut ssh) -> libc::c_int {
    ssh_remote_ipaddr(ssh);
    return (*ssh).local_port;
}
pub unsafe extern "C" fn ssh_packet_rdomain_in(mut ssh: *mut ssh) -> *const libc::c_char {
    if !((*ssh).rdomain_in).is_null() {
        return (*ssh).rdomain_in;
    }
    if ssh_packet_connection_is_on_socket(ssh) == 0 {
        return 0 as *const libc::c_char;
    }
    (*ssh).rdomain_in = get_rdomain((*(*ssh).state).connection_in);
    return (*ssh).rdomain_in;
}
unsafe extern "C" fn ssh_packet_close_internal(mut ssh: *mut ssh, mut do_close: libc::c_int) {
    let mut state: *mut session_state = (*ssh).state;
    let mut mode: u_int = 0;
    if (*state).initialized == 0 {
        return;
    }
    (*state).initialized = 0 as libc::c_int;
    if do_close != 0 {
        if (*state).connection_in == (*state).connection_out {
            close((*state).connection_out);
        } else {
            close((*state).connection_in);
            close((*state).connection_out);
        }
    }
    crate::sshbuf::sshbuf_free((*state).input);
    crate::sshbuf::sshbuf_free((*state).output);
    crate::sshbuf::sshbuf_free((*state).outgoing_packet);
    crate::sshbuf::sshbuf_free((*state).incoming_packet);
    mode = 0 as libc::c_int as u_int;
    while mode < MODE_MAX as libc::c_int as libc::c_uint {
        kex_free_newkeys((*state).newkeys[mode as usize]);
        (*state).newkeys[mode as usize] = 0 as *mut newkeys;
        ssh_clear_newkeys(ssh, mode as libc::c_int);
        mode = mode.wrapping_add(1);
        mode;
    }
    if do_close != 0 && !((*state).compression_buffer).is_null() {
        crate::sshbuf::sshbuf_free((*state).compression_buffer);
        if (*state).compression_out_started != 0 {
            let mut stream: z_streamp = &mut (*state).compression_out_stream;
            crate::log::sshlog(
                b"packet.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"ssh_packet_close_internal\0",
                ))
                .as_ptr(),
                618 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"compress outgoing: raw data %llu, compressed %llu, factor %.2f\0" as *const u8
                    as *const libc::c_char,
                (*stream).total_in as libc::c_ulonglong,
                (*stream).total_out as libc::c_ulonglong,
                if (*stream).total_in == 0 as libc::c_int as libc::c_ulong {
                    0.0f64
                } else {
                    (*stream).total_out as libc::c_double / (*stream).total_in as libc::c_double
                },
            );
            if (*state).compression_out_failures == 0 as libc::c_int {
                deflateEnd(stream);
            }
        }
        if (*state).compression_in_started != 0 {
            let mut stream_0: z_streamp = &mut (*state).compression_in_stream;
            crate::log::sshlog(
                b"packet.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"ssh_packet_close_internal\0",
                ))
                .as_ptr(),
                629 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"compress incoming: raw data %llu, compressed %llu, factor %.2f\0" as *const u8
                    as *const libc::c_char,
                (*stream_0).total_out as libc::c_ulonglong,
                (*stream_0).total_in as libc::c_ulonglong,
                if (*stream_0).total_out == 0 as libc::c_int as libc::c_ulong {
                    0.0f64
                } else {
                    (*stream_0).total_in as libc::c_double / (*stream_0).total_out as libc::c_double
                },
            );
            if (*state).compression_in_failures == 0 as libc::c_int {
                inflateEnd(stream_0);
            }
        }
    }
    cipher_free((*state).send_context);
    cipher_free((*state).receive_context);
    (*state).receive_context = 0 as *mut sshcipher_ctx;
    (*state).send_context = (*state).receive_context;
    if do_close != 0 {
        libc::free((*ssh).local_ipaddr as *mut libc::c_void);
        (*ssh).local_ipaddr = 0 as *mut libc::c_char;
        libc::free((*ssh).remote_ipaddr as *mut libc::c_void);
        (*ssh).remote_ipaddr = 0 as *mut libc::c_char;
        libc::free((*ssh).state as *mut libc::c_void);
        (*ssh).state = 0 as *mut session_state;
        kex_free((*ssh).kex);
        (*ssh).kex = 0 as *mut kex;
    }
}
pub unsafe extern "C" fn ssh_packet_close(mut ssh: *mut ssh) {
    ssh_packet_close_internal(ssh, 1 as libc::c_int);
}
pub unsafe extern "C" fn ssh_packet_clear_keys(mut ssh: *mut ssh) {
    ssh_packet_close_internal(ssh, 0 as libc::c_int);
}
pub unsafe extern "C" fn ssh_packet_set_protocol_flags(
    mut ssh: *mut ssh,
    mut protocol_flags: u_int,
) {
    (*(*ssh).state).remote_protocol_flags = protocol_flags;
}
pub unsafe extern "C" fn ssh_packet_get_protocol_flags(mut ssh: *mut ssh) -> u_int {
    return (*(*ssh).state).remote_protocol_flags;
}
unsafe extern "C" fn ssh_packet_init_compression(mut ssh: *mut ssh) -> libc::c_int {
    if ((*(*ssh).state).compression_buffer).is_null() && {
        (*(*ssh).state).compression_buffer = crate::sshbuf::sshbuf_new();
        ((*(*ssh).state).compression_buffer).is_null()
    } {
        return -(2 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn start_compression_out(
    mut ssh: *mut ssh,
    mut level: libc::c_int,
) -> libc::c_int {
    if level < 1 as libc::c_int || level > 9 as libc::c_int {
        return -(10 as libc::c_int);
    }
    crate::log::sshlog(
        b"packet.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"start_compression_out\0"))
            .as_ptr(),
        698 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Enabling compression at level %d.\0" as *const u8 as *const libc::c_char,
        level,
    );
    if (*(*ssh).state).compression_out_started == 1 as libc::c_int {
        deflateEnd(&mut (*(*ssh).state).compression_out_stream);
    }
    match deflateInit_(
        &mut (*(*ssh).state).compression_out_stream,
        level,
        b"1.2.11\0" as *const u8 as *const libc::c_char,
        ::core::mem::size_of::<z_stream>() as libc::c_ulong as libc::c_int,
    ) {
        0 => {
            (*(*ssh).state).compression_out_started = 1 as libc::c_int;
        }
        -4 => return -(2 as libc::c_int),
        _ => return -(1 as libc::c_int),
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn start_compression_in(mut ssh: *mut ssh) -> libc::c_int {
    if (*(*ssh).state).compression_in_started == 1 as libc::c_int {
        inflateEnd(&mut (*(*ssh).state).compression_in_stream);
    }
    match inflateInit_(
        &mut (*(*ssh).state).compression_in_stream,
        b"1.2.11\0" as *const u8 as *const libc::c_char,
        ::core::mem::size_of::<z_stream>() as libc::c_ulong as libc::c_int,
    ) {
        0 => {
            (*(*ssh).state).compression_in_started = 1 as libc::c_int;
        }
        -4 => return -(2 as libc::c_int),
        _ => return -(1 as libc::c_int),
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn compress_buffer(
    mut ssh: *mut ssh,
    mut in_0: *mut crate::sshbuf::sshbuf,
    mut out: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut buf: [u_char; 4096] = [0; 4096];
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 0;
    if (*(*ssh).state).compression_out_started != 1 as libc::c_int {
        return -(1 as libc::c_int);
    }
    if crate::sshbuf::sshbuf_len(in_0) == 0 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    (*(*ssh).state).compression_out_stream.next_in = sshbuf_mutable_ptr(in_0);
    if ((*(*ssh).state).compression_out_stream.next_in).is_null() {
        return -(1 as libc::c_int);
    }
    (*(*ssh).state).compression_out_stream.avail_in = crate::sshbuf::sshbuf_len(in_0) as uInt;
    loop {
        (*(*ssh).state).compression_out_stream.next_out = buf.as_mut_ptr();
        (*(*ssh).state).compression_out_stream.avail_out =
            ::core::mem::size_of::<[u_char; 4096]>() as libc::c_ulong as uInt;
        status = deflate(
            &mut (*(*ssh).state).compression_out_stream,
            1 as libc::c_int,
        );
        match status {
            -4 => return -(2 as libc::c_int),
            0 => {
                r = sshbuf_put(
                    out,
                    buf.as_mut_ptr() as *const libc::c_void,
                    (::core::mem::size_of::<[u_char; 4096]>() as libc::c_ulong).wrapping_sub(
                        (*(*ssh).state).compression_out_stream.avail_out as libc::c_ulong,
                    ),
                );
                if r != 0 as libc::c_int {
                    return r;
                }
            }
            -2 | _ => {
                (*(*ssh).state).compression_out_failures += 1;
                (*(*ssh).state).compression_out_failures;
                return -(4 as libc::c_int);
            }
        }
        if !((*(*ssh).state).compression_out_stream.avail_out == 0 as libc::c_int as libc::c_uint) {
            break;
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn uncompress_buffer(
    mut ssh: *mut ssh,
    mut in_0: *mut crate::sshbuf::sshbuf,
    mut out: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut buf: [u_char; 4096] = [0; 4096];
    let mut r: libc::c_int = 0;
    let mut status: libc::c_int = 0;
    if (*(*ssh).state).compression_in_started != 1 as libc::c_int {
        return -(1 as libc::c_int);
    }
    (*(*ssh).state).compression_in_stream.next_in = sshbuf_mutable_ptr(in_0);
    if ((*(*ssh).state).compression_in_stream.next_in).is_null() {
        return -(1 as libc::c_int);
    }
    (*(*ssh).state).compression_in_stream.avail_in = crate::sshbuf::sshbuf_len(in_0) as uInt;
    loop {
        (*(*ssh).state).compression_in_stream.next_out = buf.as_mut_ptr();
        (*(*ssh).state).compression_in_stream.avail_out =
            ::core::mem::size_of::<[u_char; 4096]>() as libc::c_ulong as uInt;
        status = inflate(&mut (*(*ssh).state).compression_in_stream, 2 as libc::c_int);
        match status {
            0 => {
                r = sshbuf_put(
                    out,
                    buf.as_mut_ptr() as *const libc::c_void,
                    (::core::mem::size_of::<[u_char; 4096]>() as libc::c_ulong).wrapping_sub(
                        (*(*ssh).state).compression_in_stream.avail_out as libc::c_ulong,
                    ),
                );
                if r != 0 as libc::c_int {
                    return r;
                }
            }
            -5 => return 0 as libc::c_int,
            -3 => return -(4 as libc::c_int),
            -4 => return -(2 as libc::c_int),
            -2 | _ => {
                (*(*ssh).state).compression_in_failures += 1;
                (*(*ssh).state).compression_in_failures;
                return -(1 as libc::c_int);
            }
        }
    }
}
pub unsafe extern "C" fn ssh_clear_newkeys(mut ssh: *mut ssh, mut mode: libc::c_int) {
    if !((*ssh).kex).is_null() && !((*(*ssh).kex).newkeys[mode as usize]).is_null() {
        kex_free_newkeys((*(*ssh).kex).newkeys[mode as usize]);
        (*(*ssh).kex).newkeys[mode as usize] = 0 as *mut newkeys;
    }
}
pub unsafe extern "C" fn ssh_set_newkeys(mut ssh: *mut ssh, mut mode: libc::c_int) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut enc: *mut sshenc = 0 as *mut sshenc;
    let mut mac: *mut sshmac = 0 as *mut sshmac;
    let mut comp: *mut sshcomp = 0 as *mut sshcomp;
    let mut ccp: *mut *mut sshcipher_ctx = 0 as *mut *mut sshcipher_ctx;
    let mut ps: *mut packet_state = 0 as *mut packet_state;
    let mut max_blocks: *mut u_int64_t = 0 as *mut u_int64_t;
    let mut wmsg: *const libc::c_char = 0 as *const libc::c_char;
    let mut r: libc::c_int = 0;
    let mut crypt_type: libc::c_int = 0;
    let mut dir: *const libc::c_char = if mode == MODE_OUT as libc::c_int {
        b"out\0" as *const u8 as *const libc::c_char
    } else {
        b"in\0" as *const u8 as *const libc::c_char
    };
    crate::log::sshlog(
        b"packet.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"ssh_set_newkeys\0")).as_ptr(),
        874 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"mode %d\0" as *const u8 as *const libc::c_char,
        mode,
    );
    if mode == MODE_OUT as libc::c_int {
        ccp = &mut (*state).send_context;
        crypt_type = 1 as libc::c_int;
        ps = &mut (*state).p_send;
        max_blocks = &mut (*state).max_blocks_out;
    } else {
        ccp = &mut (*state).receive_context;
        crypt_type = 0 as libc::c_int;
        ps = &mut (*state).p_read;
        max_blocks = &mut (*state).max_blocks_in;
    }
    if !((*state).newkeys[mode as usize]).is_null() {
        crate::log::sshlog(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"ssh_set_newkeys\0"))
                .as_ptr(),
            893 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"rekeying %s, input %llu bytes %llu blocks, output %llu bytes %llu blocks\0"
                as *const u8 as *const libc::c_char,
            dir,
            (*state).p_read.bytes as libc::c_ulonglong,
            (*state).p_read.blocks as libc::c_ulonglong,
            (*state).p_send.bytes as libc::c_ulonglong,
            (*state).p_send.blocks as libc::c_ulonglong,
        );
        kex_free_newkeys((*state).newkeys[mode as usize]);
        (*state).newkeys[mode as usize] = 0 as *mut newkeys;
    }
    (*ps).blocks = 0 as libc::c_int as u_int64_t;
    (*ps).packets = (*ps).blocks as u_int32_t;
    (*state).newkeys[mode as usize] = (*(*ssh).kex).newkeys[mode as usize];
    if ((*state).newkeys[mode as usize]).is_null() {
        return -(1 as libc::c_int);
    }
    (*(*ssh).kex).newkeys[mode as usize] = 0 as *mut newkeys;
    enc = &mut (**((*state).newkeys).as_mut_ptr().offset(mode as isize)).enc;
    mac = &mut (**((*state).newkeys).as_mut_ptr().offset(mode as isize)).mac;
    comp = &mut (**((*state).newkeys).as_mut_ptr().offset(mode as isize)).comp;
    if cipher_authlen((*enc).cipher) == 0 as libc::c_int as libc::c_uint {
        r = mac_init(mac);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    (*mac).enabled = 1 as libc::c_int;
    cipher_free(*ccp);
    *ccp = 0 as *mut sshcipher_ctx;
    r = cipher_init(
        ccp,
        (*enc).cipher,
        (*enc).key,
        (*enc).key_len,
        (*enc).iv,
        (*enc).iv_len,
        crypt_type,
    );
    if r != 0 as libc::c_int {
        return r;
    }
    if (*state).cipher_warning_done == 0 && {
        wmsg = cipher_warning_message(*ccp);
        !wmsg.is_null()
    } {
        crate::log::sshlog(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"ssh_set_newkeys\0"))
                .as_ptr(),
            919 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Warning: %s\0" as *const u8 as *const libc::c_char,
            wmsg,
        );
        (*state).cipher_warning_done = 1 as libc::c_int;
    }
    if ((*comp).type_0 == 1 as libc::c_int as libc::c_uint
        || (*comp).type_0 == 2 as libc::c_int as libc::c_uint && (*state).after_authentication != 0)
        && (*comp).enabled == 0 as libc::c_int
    {
        r = ssh_packet_init_compression(ssh);
        if r < 0 as libc::c_int {
            return r;
        }
        if mode == MODE_OUT as libc::c_int {
            r = start_compression_out(ssh, 6 as libc::c_int);
            if r != 0 as libc::c_int {
                return r;
            }
        } else {
            r = start_compression_in(ssh);
            if r != 0 as libc::c_int {
                return r;
            }
        }
        (*comp).enabled = 1 as libc::c_int;
    }
    if (*enc).block_size >= 16 as libc::c_int as libc::c_uint {
        *max_blocks = (1 as libc::c_int as u_int64_t)
            << ((*enc).block_size).wrapping_mul(2 as libc::c_int as libc::c_uint);
    } else {
        *max_blocks = ((1 as libc::c_int as u_int64_t) << 30 as libc::c_int)
            .wrapping_div((*enc).block_size as libc::c_ulong);
    }
    if (*state).rekey_limit != 0 {
        *max_blocks = if *max_blocks
            < ((*state).rekey_limit).wrapping_div((*enc).block_size as libc::c_ulong)
        {
            *max_blocks
        } else {
            ((*state).rekey_limit).wrapping_div((*enc).block_size as libc::c_ulong)
        };
    }
    crate::log::sshlog(
        b"packet.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"ssh_set_newkeys\0")).as_ptr(),
        953 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"rekey %s after %llu blocks\0" as *const u8 as *const libc::c_char,
        dir,
        *max_blocks as libc::c_ulonglong,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_packet_need_rekeying(
    mut ssh: *mut ssh,
    mut outbound_packet_len: u_int,
) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut out_blocks: u_int32_t = 0;
    if (*state).after_authentication == 0 {
        return 0 as libc::c_int;
    }
    if ssh_packet_is_rekeying(ssh) != 0 {
        return 0 as libc::c_int;
    }
    if (*ssh).compat & 0x8000 as libc::c_int != 0 {
        return 0 as libc::c_int;
    }
    if (*state).p_send.packets == 0 as libc::c_int as libc::c_uint
        && (*state).p_read.packets == 0 as libc::c_int as libc::c_uint
    {
        return 0 as libc::c_int;
    }
    if (*state).rekey_interval != 0 as libc::c_int as libc::c_uint
        && (*state).rekey_time + (*state).rekey_interval as libc::c_long <= monotime()
    {
        return 1 as libc::c_int;
    }
    if (*state).p_send.packets > (1 as libc::c_uint) << 31 as libc::c_int
        || (*state).p_read.packets > (1 as libc::c_uint) << 31 as libc::c_int
    {
        return 1 as libc::c_int;
    }
    out_blocks = outbound_packet_len
        .wrapping_add(
            ((*(*state).newkeys[MODE_OUT as libc::c_int as usize])
                .enc
                .block_size)
                .wrapping_sub(1 as libc::c_int as libc::c_uint),
        )
        .wrapping_div(
            (*(*state).newkeys[MODE_OUT as libc::c_int as usize])
                .enc
                .block_size,
        )
        .wrapping_mul(
            (*(*state).newkeys[MODE_OUT as libc::c_int as usize])
                .enc
                .block_size,
        );
    return ((*state).max_blocks_out != 0
        && ((*state).p_send.blocks).wrapping_add(out_blocks as libc::c_ulong)
            > (*state).max_blocks_out
        || (*state).max_blocks_in != 0 && (*state).p_read.blocks > (*state).max_blocks_in)
        as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_check_rekey(mut ssh: *mut ssh) -> libc::c_int {
    if ssh_packet_need_rekeying(ssh, 0 as libc::c_int as u_int) == 0 {
        return 0 as libc::c_int;
    }
    crate::log::sshlog(
        b"packet.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"ssh_packet_check_rekey\0"))
            .as_ptr(),
        1010 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"rekex triggered\0" as *const u8 as *const libc::c_char,
    );
    return kex_start_rekex(ssh);
}
unsafe extern "C" fn ssh_packet_enable_delayed_compress(mut ssh: *mut ssh) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut comp: *mut sshcomp = 0 as *mut sshcomp;
    let mut r: libc::c_int = 0;
    let mut mode: libc::c_int = 0;
    (*state).after_authentication = 1 as libc::c_int;
    mode = 0 as libc::c_int;
    while mode < MODE_MAX as libc::c_int {
        if !((*state).newkeys[mode as usize]).is_null() {
            comp = &mut (**((*state).newkeys).as_mut_ptr().offset(mode as isize)).comp;
            if !comp.is_null()
                && (*comp).enabled == 0
                && (*comp).type_0 == 2 as libc::c_int as libc::c_uint
            {
                r = ssh_packet_init_compression(ssh);
                if r != 0 as libc::c_int {
                    return r;
                }
                if mode == MODE_OUT as libc::c_int {
                    r = start_compression_out(ssh, 6 as libc::c_int);
                    if r != 0 as libc::c_int {
                        return r;
                    }
                } else {
                    r = start_compression_in(ssh);
                    if r != 0 as libc::c_int {
                        return r;
                    }
                }
                (*comp).enabled = 1 as libc::c_int;
            }
        }
        mode += 1;
        mode;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_log_type(mut type_0: u_char) -> libc::c_int {
    match type_0 as libc::c_int {
        94 | 95 | 93 => return 0 as libc::c_int,
        _ => return 1 as libc::c_int,
    };
}
pub unsafe extern "C" fn ssh_packet_send2_wrapped(mut ssh: *mut ssh) -> libc::c_int {
    let mut current_block: u64;
    let mut state: *mut session_state = (*ssh).state;
    let mut type_0: u_char = 0;
    let mut cp: *mut u_char = 0 as *mut u_char;
    let mut macbuf: [u_char; 64] = [0; 64];
    let mut tmp: u_char = 0;
    let mut padlen: u_char = 0;
    let mut pad: u_char = 0 as libc::c_int as u_char;
    let mut authlen: u_int = 0 as libc::c_int as u_int;
    let mut aadlen: u_int = 0 as libc::c_int as u_int;
    let mut len: u_int = 0;
    let mut enc: *mut sshenc = 0 as *mut sshenc;
    let mut mac: *mut sshmac = 0 as *mut sshmac;
    let mut comp: *mut sshcomp = 0 as *mut sshcomp;
    let mut r: libc::c_int = 0;
    let mut block_size: libc::c_int = 0;
    if !((*state).newkeys[MODE_OUT as libc::c_int as usize]).is_null() {
        enc = &mut (**((*state).newkeys)
            .as_mut_ptr()
            .offset(MODE_OUT as libc::c_int as isize))
        .enc;
        mac = &mut (**((*state).newkeys)
            .as_mut_ptr()
            .offset(MODE_OUT as libc::c_int as isize))
        .mac;
        comp = &mut (**((*state).newkeys)
            .as_mut_ptr()
            .offset(MODE_OUT as libc::c_int as isize))
        .comp;
        authlen = cipher_authlen((*enc).cipher);
        if authlen != 0 as libc::c_int as libc::c_uint {
            mac = 0 as *mut sshmac;
        }
    }
    block_size = (if !enc.is_null() {
        (*enc).block_size
    } else {
        8 as libc::c_int as libc::c_uint
    }) as libc::c_int;
    aadlen = (if !mac.is_null() && (*mac).enabled != 0 && (*mac).etm != 0 || authlen != 0 {
        4 as libc::c_int
    } else {
        0 as libc::c_int
    }) as u_int;
    type_0 = *(sshbuf_ptr((*state).outgoing_packet)).offset(5 as libc::c_int as isize);
    if ssh_packet_log_type(type_0) != 0 {
        crate::log::sshlog(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"ssh_packet_send2_wrapped\0",
            ))
            .as_ptr(),
            1095 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"send packet: type %u\0" as *const u8 as *const libc::c_char,
            type_0 as libc::c_int,
        );
    }
    if !comp.is_null() && (*comp).enabled != 0 {
        len = crate::sshbuf::sshbuf_len((*state).outgoing_packet) as u_int;
        r = sshbuf_consume((*state).outgoing_packet, 5 as libc::c_int as size_t);
        if r != 0 as libc::c_int {
            current_block = 17000309712211423364;
        } else {
            crate::sshbuf::sshbuf_reset((*state).compression_buffer);
            r = compress_buffer(ssh, (*state).outgoing_packet, (*state).compression_buffer);
            if r != 0 as libc::c_int {
                current_block = 17000309712211423364;
            } else {
                crate::sshbuf::sshbuf_reset((*state).outgoing_packet);
                r = sshbuf_put(
                    (*state).outgoing_packet,
                    b"\0\0\0\0\0\0" as *const u8 as *const libc::c_char as *const libc::c_void,
                    5 as libc::c_int as size_t,
                );
                if r != 0 as libc::c_int || {
                    r = sshbuf_putb((*state).outgoing_packet, (*state).compression_buffer);
                    r != 0 as libc::c_int
                } {
                    current_block = 17000309712211423364;
                } else {
                    current_block = 6057473163062296781;
                }
            }
        }
    } else {
        current_block = 6057473163062296781;
    }
    match current_block {
        6057473163062296781 => {
            len = crate::sshbuf::sshbuf_len((*state).outgoing_packet) as u_int;
            len = (len as libc::c_uint).wrapping_sub(aadlen) as u_int as u_int;
            padlen = (block_size as libc::c_uint)
                .wrapping_sub(len.wrapping_rem(block_size as libc::c_uint))
                as u_char;
            if (padlen as libc::c_int) < 4 as libc::c_int {
                padlen = (padlen as libc::c_int + block_size) as u_char;
            }
            if (*state).extra_pad != 0 {
                tmp = (*state).extra_pad;
                (*state).extra_pad = (((*state).extra_pad as libc::c_int
                    + (block_size - 1 as libc::c_int))
                    / block_size
                    * block_size) as u_char;
                if ((*state).extra_pad as libc::c_int) < tmp as libc::c_int {
                    return -(10 as libc::c_int);
                }
                tmp = len
                    .wrapping_add(padlen as libc::c_uint)
                    .wrapping_rem((*state).extra_pad as libc::c_uint)
                    as u_char;
                if tmp as libc::c_int > (*state).extra_pad as libc::c_int {
                    return -(10 as libc::c_int);
                }
                pad = ((*state).extra_pad as libc::c_int - tmp as libc::c_int) as u_char;
                tmp = padlen;
                padlen = (padlen as libc::c_int + pad as libc::c_int) as u_char;
                if (padlen as libc::c_int) < tmp as libc::c_int {
                    return -(10 as libc::c_int);
                }
                (*state).extra_pad = 0 as libc::c_int as u_char;
            }
            r = sshbuf_reserve((*state).outgoing_packet, padlen as size_t, &mut cp);
            if !(r != 0 as libc::c_int) {
                if !enc.is_null() && cipher_ctx_is_plaintext((*state).send_context) == 0 {
                    arc4random_buf(cp as *mut libc::c_void, padlen as size_t);
                } else {
                    explicit_bzero(cp as *mut libc::c_void, padlen as size_t);
                }
                len = crate::sshbuf::sshbuf_len((*state).outgoing_packet) as u_int;
                cp = sshbuf_mutable_ptr((*state).outgoing_packet);
                if cp.is_null() {
                    r = -(1 as libc::c_int);
                } else {
                    let __v: u_int32_t = len.wrapping_sub(4 as libc::c_int as libc::c_uint);
                    *cp.offset(0 as libc::c_int as isize) =
                        (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
                    *cp.offset(1 as libc::c_int as isize) =
                        (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
                    *cp.offset(2 as libc::c_int as isize) =
                        (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
                    *cp.offset(3 as libc::c_int as isize) =
                        (__v & 0xff as libc::c_int as libc::c_uint) as u_char;
                    *cp.offset(4 as libc::c_int as isize) = padlen;
                    if !mac.is_null() && (*mac).enabled != 0 && (*mac).etm == 0 {
                        r = mac_compute(
                            mac,
                            (*state).p_send.seqnr,
                            sshbuf_ptr((*state).outgoing_packet),
                            len as libc::c_int,
                            macbuf.as_mut_ptr(),
                            ::core::mem::size_of::<[u_char; 64]>() as libc::c_ulong,
                        );
                        if r != 0 as libc::c_int {
                            current_block = 17000309712211423364;
                        } else {
                            current_block = 1423531122933789233;
                        }
                    } else {
                        current_block = 1423531122933789233;
                    }
                    match current_block {
                        17000309712211423364 => {}
                        _ => {
                            r = sshbuf_reserve(
                                (*state).output,
                                (crate::sshbuf::sshbuf_len((*state).outgoing_packet))
                                    .wrapping_add(authlen as libc::c_ulong),
                                &mut cp,
                            );
                            if !(r != 0 as libc::c_int) {
                                r = cipher_crypt(
                                    (*state).send_context,
                                    (*state).p_send.seqnr,
                                    cp,
                                    sshbuf_ptr((*state).outgoing_packet),
                                    len.wrapping_sub(aadlen),
                                    aadlen,
                                    authlen,
                                );
                                if !(r != 0 as libc::c_int) {
                                    if !mac.is_null() && (*mac).enabled != 0 {
                                        if (*mac).etm != 0 {
                                            r = mac_compute(
                                                mac,
                                                (*state).p_send.seqnr,
                                                cp,
                                                len as libc::c_int,
                                                macbuf.as_mut_ptr(),
                                                ::core::mem::size_of::<[u_char; 64]>()
                                                    as libc::c_ulong,
                                            );
                                            if r != 0 as libc::c_int {
                                                current_block = 17000309712211423364;
                                            } else {
                                                current_block = 10753070352654377903;
                                            }
                                        } else {
                                            current_block = 10753070352654377903;
                                        }
                                        match current_block {
                                            17000309712211423364 => {}
                                            _ => {
                                                r = sshbuf_put(
                                                    (*state).output,
                                                    macbuf.as_mut_ptr() as *const libc::c_void,
                                                    (*mac).mac_len as size_t,
                                                );
                                                if r != 0 as libc::c_int {
                                                    current_block = 17000309712211423364;
                                                } else {
                                                    current_block = 2520131295878969859;
                                                }
                                            }
                                        }
                                    } else {
                                        current_block = 2520131295878969859;
                                    }
                                    match current_block {
                                        17000309712211423364 => {}
                                        _ => {
                                            (*state).p_send.seqnr =
                                                ((*state).p_send.seqnr).wrapping_add(1);
                                            if (*state).p_send.seqnr
                                                == 0 as libc::c_int as libc::c_uint
                                            {
                                                crate::log::sshlog(
                                                    b"packet.c\0" as *const u8
                                                        as *const libc::c_char,
                                                    (*::core::mem::transmute::<
                                                        &[u8; 25],
                                                        &[libc::c_char; 25],
                                                    >(
                                                        b"ssh_packet_send2_wrapped\0"
                                                    ))
                                                    .as_ptr(),
                                                    1209 as libc::c_int,
                                                    0 as libc::c_int,
                                                    SYSLOG_LEVEL_INFO,
                                                    0 as *const libc::c_char,
                                                    b"outgoing seqnr wraps around\0" as *const u8
                                                        as *const libc::c_char,
                                                );
                                            }
                                            (*state).p_send.packets =
                                                ((*state).p_send.packets).wrapping_add(1);
                                            if (*state).p_send.packets
                                                == 0 as libc::c_int as libc::c_uint
                                            {
                                                if (*ssh).compat & 0x8000 as libc::c_int == 0 {
                                                    return -(39 as libc::c_int);
                                                }
                                            }
                                            (*state).p_send.blocks = ((*state).p_send.blocks
                                                as libc::c_ulong)
                                                .wrapping_add(
                                                    len.wrapping_div(block_size as libc::c_uint)
                                                        as libc::c_ulong,
                                                )
                                                as u_int64_t
                                                as u_int64_t;
                                            (*state).p_send.bytes = ((*state).p_send.bytes
                                                as libc::c_ulong)
                                                .wrapping_add(len as libc::c_ulong)
                                                as u_int64_t
                                                as u_int64_t;
                                            crate::sshbuf::sshbuf_reset((*state).outgoing_packet);
                                            if type_0 as libc::c_int == 21 as libc::c_int {
                                                r = ssh_set_newkeys(ssh, MODE_OUT as libc::c_int);
                                            } else if type_0 as libc::c_int == 52 as libc::c_int
                                                && (*state).server_side != 0
                                            {
                                                r = ssh_packet_enable_delayed_compress(ssh);
                                            } else {
                                                r = 0 as libc::c_int;
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
        _ => {}
    }
    return r;
}
unsafe extern "C" fn ssh_packet_type_is_kex(mut type_0: u_char) -> libc::c_int {
    return (type_0 as libc::c_int >= 1 as libc::c_int
        && type_0 as libc::c_int <= 49 as libc::c_int
        && type_0 as libc::c_int != 5 as libc::c_int
        && type_0 as libc::c_int != 6 as libc::c_int
        && type_0 as libc::c_int != 7 as libc::c_int) as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_send2(mut ssh: *mut ssh) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut p: *mut packet = 0 as *mut packet;
    let mut type_0: u_char = 0;
    let mut r: libc::c_int = 0;
    let mut need_rekey: libc::c_int = 0;
    if crate::sshbuf::sshbuf_len((*state).outgoing_packet) < 6 as libc::c_int as libc::c_ulong {
        return -(1 as libc::c_int);
    }
    type_0 = *(sshbuf_ptr((*state).outgoing_packet)).offset(5 as libc::c_int as isize);
    need_rekey = (ssh_packet_type_is_kex(type_0) == 0
        && ssh_packet_need_rekeying(
            ssh,
            crate::sshbuf::sshbuf_len((*state).outgoing_packet) as u_int,
        ) != 0) as libc::c_int;
    if (need_rekey != 0 || (*state).rekeying != 0) && ssh_packet_type_is_kex(type_0) == 0 {
        if need_rekey != 0 {
            crate::log::sshlog(
                b"packet.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"ssh_packet_send2\0"))
                    .as_ptr(),
                1259 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"rekex triggered\0" as *const u8 as *const libc::c_char,
            );
        }
        crate::log::sshlog(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"ssh_packet_send2\0"))
                .as_ptr(),
            1260 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"enqueue packet: %u\0" as *const u8 as *const libc::c_char,
            type_0 as libc::c_int,
        );
        p = calloc(
            1 as libc::c_int as libc::c_ulong,
            ::core::mem::size_of::<packet>() as libc::c_ulong,
        ) as *mut packet;
        if p.is_null() {
            return -(2 as libc::c_int);
        }
        (*p).type_0 = type_0;
        (*p).payload = (*state).outgoing_packet;
        (*p).next.tqe_next = 0 as *mut packet;
        (*p).next.tqe_prev = (*state).outgoing.tqh_last;
        *(*state).outgoing.tqh_last = p;
        (*state).outgoing.tqh_last = &mut (*p).next.tqe_next;
        (*state).outgoing_packet = crate::sshbuf::sshbuf_new();
        if ((*state).outgoing_packet).is_null() {
            return -(2 as libc::c_int);
        }
        if need_rekey != 0 {
            return kex_start_rekex(ssh);
        }
        return 0 as libc::c_int;
    }
    if type_0 as libc::c_int == 20 as libc::c_int {
        (*state).rekeying = 1 as libc::c_int;
    }
    r = ssh_packet_send2_wrapped(ssh);
    if r != 0 as libc::c_int {
        return r;
    }
    if type_0 as libc::c_int == 21 as libc::c_int {
        (*state).rekeying = 0 as libc::c_int;
        (*state).rekey_time = monotime();
        loop {
            p = (*state).outgoing.tqh_first;
            if p.is_null() {
                break;
            }
            type_0 = (*p).type_0;
            if ssh_packet_need_rekeying(ssh, crate::sshbuf::sshbuf_len((*p).payload) as u_int) != 0
            {
                crate::log::sshlog(
                    b"packet.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(
                        b"ssh_packet_send2\0",
                    ))
                    .as_ptr(),
                    1301 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"queued packet triggered rekex\0" as *const u8 as *const libc::c_char,
                );
                return kex_start_rekex(ssh);
            }
            crate::log::sshlog(
                b"packet.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"ssh_packet_send2\0"))
                    .as_ptr(),
                1304 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"dequeue packet: %u\0" as *const u8 as *const libc::c_char,
                type_0 as libc::c_int,
            );
            crate::sshbuf::sshbuf_free((*state).outgoing_packet);
            (*state).outgoing_packet = (*p).payload;
            if !((*p).next.tqe_next).is_null() {
                (*(*p).next.tqe_next).next.tqe_prev = (*p).next.tqe_prev;
            } else {
                (*state).outgoing.tqh_last = (*p).next.tqe_prev;
            }
            *(*p).next.tqe_prev = (*p).next.tqe_next;
            memset(
                p as *mut libc::c_void,
                0 as libc::c_int,
                ::core::mem::size_of::<packet>() as libc::c_ulong,
            );
            libc::free(p as *mut libc::c_void);
            r = ssh_packet_send2_wrapped(ssh);
            if r != 0 as libc::c_int {
                return r;
            }
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_read_seqnr(
    mut ssh: *mut ssh,
    mut typep: *mut u_char,
    mut seqnr_p: *mut u_int32_t,
) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut len: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut ms_remain: libc::c_int = 0 as libc::c_int;
    let mut pfd: pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    let mut buf: [libc::c_char; 8192] = [0; 8192];
    let mut start: libc::timeval = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut timespec: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut timespecp: *mut libc::timespec = 0 as *mut libc::timespec;
    r = ssh_packet_write_wait(ssh);
    if !(r != 0 as libc::c_int) {
        's_26: loop {
            r = ssh_packet_read_poll_seqnr(ssh, typep, seqnr_p);
            if r != 0 as libc::c_int {
                break;
            }
            if *typep as libc::c_int != 0 as libc::c_int {
                break;
            }
            pfd.fd = (*state).connection_in;
            pfd.events = 0x1 as libc::c_int as libc::c_short;
            if (*state).packet_timeout_ms > 0 as libc::c_int {
                ms_remain = (*state).packet_timeout_ms;
                timespecp = &mut timespec;
            }
            loop {
                if (*state).packet_timeout_ms > 0 as libc::c_int {
                    ms_to_timespec(&mut timespec, ms_remain);
                    monotime_tv(&mut start);
                }
                r = ppoll(
                    &mut pfd,
                    1 as libc::c_int as nfds_t,
                    timespecp,
                    0 as *const __sigset_t,
                );
                if r >= 0 as libc::c_int {
                    break;
                }
                if *libc::__errno_location() != 11 as libc::c_int
                    && *libc::__errno_location() != 4 as libc::c_int
                    && *libc::__errno_location() != 11 as libc::c_int
                {
                    r = -(24 as libc::c_int);
                    break 's_26;
                } else {
                    if (*state).packet_timeout_ms <= 0 as libc::c_int {
                        continue;
                    }
                    ms_subtract_diff(&mut start, &mut ms_remain);
                    if !(ms_remain <= 0 as libc::c_int) {
                        continue;
                    }
                    r = 0 as libc::c_int;
                    break;
                }
            }
            if r == 0 as libc::c_int {
                r = -(53 as libc::c_int);
                break;
            } else {
                len = read(
                    (*state).connection_in,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    ::core::mem::size_of::<[libc::c_char; 8192]>() as libc::c_ulong,
                ) as libc::c_int;
                if len == 0 as libc::c_int {
                    r = -(52 as libc::c_int);
                    break;
                } else if len == -(1 as libc::c_int) {
                    r = -(24 as libc::c_int);
                    break;
                } else {
                    r = ssh_packet_process_incoming(ssh, buf.as_mut_ptr(), len as u_int);
                    if r != 0 as libc::c_int {
                        break;
                    }
                }
            }
        }
    }
    return r;
}
pub unsafe extern "C" fn ssh_packet_read(mut ssh: *mut ssh) -> libc::c_int {
    let mut type_0: u_char = 0;
    let mut r: libc::c_int = 0;
    r = ssh_packet_read_seqnr(ssh, &mut type_0, 0 as *mut u_int32_t);
    if r != 0 as libc::c_int {
        sshfatal(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"ssh_packet_read\0"))
                .as_ptr(),
            1413 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"read\0" as *const u8 as *const libc::c_char,
        );
    }
    return type_0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_read_expect(
    mut ssh: *mut ssh,
    mut expected_type: u_int,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut type_0: u_char = 0;
    r = ssh_packet_read_seqnr(ssh, &mut type_0, 0 as *mut u_int32_t);
    if r != 0 as libc::c_int {
        return r;
    }
    if type_0 as libc::c_uint != expected_type {
        r = sshpkt_disconnect(
            ssh,
            b"Protocol error: expected packet type %d, got %d\0" as *const u8
                as *const libc::c_char,
            expected_type,
            type_0 as libc::c_int,
        );
        if r != 0 as libc::c_int {
            return r;
        }
        return -(55 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_packet_read_poll2_mux(
    mut ssh: *mut ssh,
    mut typep: *mut u_char,
    mut _seqnr_p: *mut u_int32_t,
) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut cp: *const u_char = 0 as *const u_char;
    let mut need: size_t = 0;
    let mut r: libc::c_int = 0;
    if !((*ssh).kex).is_null() {
        return -(1 as libc::c_int);
    }
    *typep = 0 as libc::c_int as u_char;
    cp = sshbuf_ptr((*state).input);
    if (*state).packlen == 0 as libc::c_int as libc::c_uint {
        if crate::sshbuf::sshbuf_len((*state).input)
            < (4 as libc::c_int + 1 as libc::c_int) as libc::c_ulong
        {
            return 0 as libc::c_int;
        }
        (*state).packlen = (*cp.offset(0 as libc::c_int as isize) as u_int32_t)
            << 24 as libc::c_int
            | (*cp.offset(1 as libc::c_int as isize) as u_int32_t) << 16 as libc::c_int
            | (*cp.offset(2 as libc::c_int as isize) as u_int32_t) << 8 as libc::c_int
            | *cp.offset(3 as libc::c_int as isize) as u_int32_t;
        if (*state).packlen < (4 as libc::c_int + 1 as libc::c_int) as libc::c_uint
            || (*state).packlen > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_uint
        {
            return -(3 as libc::c_int);
        }
    }
    need = ((*state).packlen).wrapping_add(4 as libc::c_int as libc::c_uint) as size_t;
    if crate::sshbuf::sshbuf_len((*state).input) < need {
        return 0 as libc::c_int;
    }
    crate::sshbuf::sshbuf_reset((*state).incoming_packet);
    r = sshbuf_put(
        (*state).incoming_packet,
        cp.offset(4 as libc::c_int as isize) as *const libc::c_void,
        (*state).packlen as size_t,
    );
    if r != 0 as libc::c_int
        || {
            r = sshbuf_consume((*state).input, need);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u8(
                (*state).incoming_packet,
                0 as *mut u_char,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u8((*state).incoming_packet, typep);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    if ssh_packet_log_type(*typep) != 0 {
        crate::log::sshlog(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"ssh_packet_read_poll2_mux\0",
            ))
            .as_ptr(),
            1471 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"type %u\0" as *const u8 as *const libc::c_char,
            *typep as libc::c_int,
        );
    }
    (*state).packlen = 0 as libc::c_int as u_int;
    return r;
}
pub unsafe extern "C" fn ssh_packet_read_poll2(
    mut ssh: *mut ssh,
    mut typep: *mut u_char,
    mut seqnr_p: *mut u_int32_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut state: *mut session_state = (*ssh).state;
    let mut padlen: u_int = 0;
    let mut need: u_int = 0;
    let mut cp: *mut u_char = 0 as *mut u_char;
    let mut maclen: u_int = 0;
    let mut aadlen: u_int = 0 as libc::c_int as u_int;
    let mut authlen: u_int = 0 as libc::c_int as u_int;
    let mut block_size: u_int = 0;
    let mut enc: *mut sshenc = 0 as *mut sshenc;
    let mut mac: *mut sshmac = 0 as *mut sshmac;
    let mut comp: *mut sshcomp = 0 as *mut sshcomp;
    let mut r: libc::c_int = 0;
    if (*state).mux != 0 {
        return ssh_packet_read_poll2_mux(ssh, typep, seqnr_p);
    }
    *typep = 0 as libc::c_int as u_char;
    if (*state).packet_discard != 0 {
        return 0 as libc::c_int;
    }
    if !((*state).newkeys[MODE_IN as libc::c_int as usize]).is_null() {
        enc = &mut (**((*state).newkeys)
            .as_mut_ptr()
            .offset(MODE_IN as libc::c_int as isize))
        .enc;
        mac = &mut (**((*state).newkeys)
            .as_mut_ptr()
            .offset(MODE_IN as libc::c_int as isize))
        .mac;
        comp = &mut (**((*state).newkeys)
            .as_mut_ptr()
            .offset(MODE_IN as libc::c_int as isize))
        .comp;
        authlen = cipher_authlen((*enc).cipher);
        if authlen != 0 as libc::c_int as libc::c_uint {
            mac = 0 as *mut sshmac;
        }
    }
    maclen = if !mac.is_null() && (*mac).enabled != 0 {
        (*mac).mac_len
    } else {
        0 as libc::c_int as libc::c_uint
    };
    block_size = if !enc.is_null() {
        (*enc).block_size
    } else {
        8 as libc::c_int as libc::c_uint
    };
    aadlen = (if !mac.is_null() && (*mac).enabled != 0 && (*mac).etm != 0 || authlen != 0 {
        4 as libc::c_int
    } else {
        0 as libc::c_int
    }) as u_int;
    if aadlen != 0 && (*state).packlen == 0 as libc::c_int as libc::c_uint {
        if cipher_get_length(
            (*state).receive_context,
            &mut (*state).packlen,
            (*state).p_read.seqnr,
            sshbuf_ptr((*state).input),
            crate::sshbuf::sshbuf_len((*state).input) as u_int,
        ) != 0 as libc::c_int
        {
            return 0 as libc::c_int;
        }
        if (*state).packlen < (1 as libc::c_int + 4 as libc::c_int) as libc::c_uint
            || (*state).packlen > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_uint
        {
            crate::log::sshlog(
                b"packet.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"ssh_packet_read_poll2\0",
                ))
                .as_ptr(),
                1520 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Bad packet length %u.\0" as *const u8 as *const libc::c_char,
                (*state).packlen,
            );
            r = sshpkt_disconnect(ssh, b"Packet corrupt\0" as *const u8 as *const libc::c_char);
            if r != 0 as libc::c_int {
                return r;
            }
            return -(54 as libc::c_int);
        }
        crate::sshbuf::sshbuf_reset((*state).incoming_packet);
        current_block = 17281240262373992796;
    } else if (*state).packlen == 0 as libc::c_int as libc::c_uint {
        if crate::sshbuf::sshbuf_len((*state).input) < block_size as libc::c_ulong {
            return 0 as libc::c_int;
        }
        crate::sshbuf::sshbuf_reset((*state).incoming_packet);
        r = sshbuf_reserve((*state).incoming_packet, block_size as size_t, &mut cp);
        if r != 0 as libc::c_int {
            current_block = 11636842938881510489;
        } else {
            r = cipher_crypt(
                (*state).receive_context,
                (*state).p_send.seqnr,
                cp,
                sshbuf_ptr((*state).input),
                block_size,
                0 as libc::c_int as u_int,
                0 as libc::c_int as u_int,
            );
            if r != 0 as libc::c_int {
                current_block = 11636842938881510489;
            } else {
                (*state).packlen = (*(sshbuf_ptr((*state).incoming_packet))
                    .offset(0 as libc::c_int as isize)
                    as u_int32_t)
                    << 24 as libc::c_int
                    | (*(sshbuf_ptr((*state).incoming_packet)).offset(1 as libc::c_int as isize)
                        as u_int32_t)
                        << 16 as libc::c_int
                    | (*(sshbuf_ptr((*state).incoming_packet)).offset(2 as libc::c_int as isize)
                        as u_int32_t)
                        << 8 as libc::c_int
                    | *(sshbuf_ptr((*state).incoming_packet)).offset(3 as libc::c_int as isize)
                        as u_int32_t;
                if (*state).packlen < (1 as libc::c_int + 4 as libc::c_int) as libc::c_uint
                    || (*state).packlen > (256 as libc::c_int * 1024 as libc::c_int) as libc::c_uint
                {
                    crate::log::sshlog(
                        b"packet.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                            b"ssh_packet_read_poll2\0",
                        ))
                        .as_ptr(),
                        1550 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        0 as *const libc::c_char,
                        b"Bad packet length %u.\0" as *const u8 as *const libc::c_char,
                        (*state).packlen,
                    );
                    return ssh_packet_start_discard(
                        ssh,
                        enc,
                        mac,
                        0 as libc::c_int as size_t,
                        (256 as libc::c_int * 1024 as libc::c_int) as u_int,
                    );
                }
                r = sshbuf_consume((*state).input, block_size as size_t);
                if r != 0 as libc::c_int {
                    current_block = 11636842938881510489;
                } else {
                    current_block = 17281240262373992796;
                }
            }
        }
    } else {
        current_block = 17281240262373992796;
    }
    match current_block {
        17281240262373992796 => {
            if aadlen != 0 {
                need = (*state).packlen;
            } else {
                need = (4 as libc::c_int as libc::c_uint)
                    .wrapping_add((*state).packlen)
                    .wrapping_sub(block_size);
            }
            if need.wrapping_rem(block_size) != 0 as libc::c_int as libc::c_uint {
                crate::log::sshlog(
                    b"packet.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"ssh_packet_read_poll2\0",
                    ))
                    .as_ptr(),
                    1573 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"padding error: need %d block %d mod %d\0" as *const u8 as *const libc::c_char,
                    need,
                    block_size,
                    need.wrapping_rem(block_size),
                );
                return ssh_packet_start_discard(
                    ssh,
                    enc,
                    mac,
                    0 as libc::c_int as size_t,
                    ((256 as libc::c_int * 1024 as libc::c_int) as libc::c_uint)
                        .wrapping_sub(block_size),
                );
            }
            if crate::sshbuf::sshbuf_len((*state).input)
                < aadlen
                    .wrapping_add(need)
                    .wrapping_add(authlen)
                    .wrapping_add(maclen) as libc::c_ulong
            {
                return 0 as libc::c_int;
            }
            if !mac.is_null() && (*mac).enabled != 0 && (*mac).etm != 0 {
                r = mac_check(
                    mac,
                    (*state).p_read.seqnr,
                    sshbuf_ptr((*state).input),
                    aadlen.wrapping_add(need) as size_t,
                    (sshbuf_ptr((*state).input))
                        .offset(aadlen as isize)
                        .offset(need as isize)
                        .offset(authlen as isize),
                    maclen as size_t,
                );
                if r != 0 as libc::c_int {
                    if r == -(30 as libc::c_int) {
                        crate::log::sshlog(
                            b"packet.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                                b"ssh_packet_read_poll2\0",
                            ))
                            .as_ptr(),
                            1598 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_INFO,
                            0 as *const libc::c_char,
                            b"Corrupted MAC on input.\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    current_block = 11636842938881510489;
                } else {
                    current_block = 1356832168064818221;
                }
            } else {
                current_block = 1356832168064818221;
            }
            match current_block {
                11636842938881510489 => {}
                _ => {
                    r = sshbuf_reserve(
                        (*state).incoming_packet,
                        aadlen.wrapping_add(need) as size_t,
                        &mut cp,
                    );
                    if !(r != 0 as libc::c_int) {
                        r = cipher_crypt(
                            (*state).receive_context,
                            (*state).p_read.seqnr,
                            cp,
                            sshbuf_ptr((*state).input),
                            need,
                            aadlen,
                            authlen,
                        );
                        if !(r != 0 as libc::c_int) {
                            r = sshbuf_consume(
                                (*state).input,
                                aadlen.wrapping_add(need).wrapping_add(authlen) as size_t,
                            );
                            if !(r != 0 as libc::c_int) {
                                if !mac.is_null() && (*mac).enabled != 0 {
                                    if (*mac).etm == 0 && {
                                        r = mac_check(
                                            mac,
                                            (*state).p_read.seqnr,
                                            sshbuf_ptr((*state).incoming_packet),
                                            crate::sshbuf::sshbuf_len((*state).incoming_packet),
                                            sshbuf_ptr((*state).input),
                                            maclen as size_t,
                                        );
                                        r != 0 as libc::c_int
                                    } {
                                        if r != -(30 as libc::c_int) {
                                            current_block = 11636842938881510489;
                                        } else {
                                            crate::log::sshlog(
                                                b"packet.c\0" as *const u8 as *const libc::c_char,
                                                (*::core::mem::transmute::<
                                                    &[u8; 22],
                                                    &[libc::c_char; 22],
                                                >(
                                                    b"ssh_packet_read_poll2\0"
                                                ))
                                                .as_ptr(),
                                                1618 as libc::c_int,
                                                0 as libc::c_int,
                                                SYSLOG_LEVEL_INFO,
                                                0 as *const libc::c_char,
                                                b"Corrupted MAC on input.\0" as *const u8
                                                    as *const libc::c_char,
                                            );
                                            if need.wrapping_add(block_size)
                                                > (256 as libc::c_int * 1024 as libc::c_int)
                                                    as libc::c_uint
                                            {
                                                return -(1 as libc::c_int);
                                            }
                                            return ssh_packet_start_discard(
                                                ssh,
                                                enc,
                                                mac,
                                                crate::sshbuf::sshbuf_len((*state).incoming_packet),
                                                ((256 as libc::c_int * 1024 as libc::c_int)
                                                    as libc::c_uint)
                                                    .wrapping_sub(need)
                                                    .wrapping_sub(block_size),
                                            );
                                        }
                                    } else {
                                        r = sshbuf_consume(
                                            (*state).input,
                                            (*mac).mac_len as size_t,
                                        );
                                        if r != 0 as libc::c_int {
                                            current_block = 11636842938881510489;
                                        } else {
                                            current_block = 9353995356876505083;
                                        }
                                    }
                                } else {
                                    current_block = 9353995356876505083;
                                }
                                match current_block {
                                    11636842938881510489 => {}
                                    _ => {
                                        if !seqnr_p.is_null() {
                                            *seqnr_p = (*state).p_read.seqnr;
                                        }
                                        (*state).p_read.seqnr =
                                            ((*state).p_read.seqnr).wrapping_add(1);
                                        if (*state).p_read.seqnr == 0 as libc::c_int as libc::c_uint
                                        {
                                            crate::log::sshlog(
                                                b"packet.c\0" as *const u8 as *const libc::c_char,
                                                (*::core::mem::transmute::<
                                                    &[u8; 22],
                                                    &[libc::c_char; 22],
                                                >(
                                                    b"ssh_packet_read_poll2\0"
                                                ))
                                                .as_ptr(),
                                                1633 as libc::c_int,
                                                0 as libc::c_int,
                                                SYSLOG_LEVEL_INFO,
                                                0 as *const libc::c_char,
                                                b"incoming seqnr wraps around\0" as *const u8
                                                    as *const libc::c_char,
                                            );
                                        }
                                        (*state).p_read.packets =
                                            ((*state).p_read.packets).wrapping_add(1);
                                        if (*state).p_read.packets
                                            == 0 as libc::c_int as libc::c_uint
                                        {
                                            if (*ssh).compat & 0x8000 as libc::c_int == 0 {
                                                return -(39 as libc::c_int);
                                            }
                                        }
                                        (*state).p_read.blocks =
                                            ((*state).p_read.blocks as libc::c_ulong).wrapping_add(
                                                ((*state).packlen)
                                                    .wrapping_add(4 as libc::c_int as libc::c_uint)
                                                    .wrapping_div(block_size)
                                                    as libc::c_ulong,
                                            )
                                                as u_int64_t
                                                as u_int64_t;
                                        (*state).p_read.bytes =
                                            ((*state).p_read.bytes as libc::c_ulong).wrapping_add(
                                                ((*state).packlen)
                                                    .wrapping_add(4 as libc::c_int as libc::c_uint)
                                                    as libc::c_ulong,
                                            )
                                                as u_int64_t
                                                as u_int64_t;
                                        padlen = *(sshbuf_ptr((*state).incoming_packet))
                                            .offset(4 as libc::c_int as isize)
                                            as u_int;
                                        if padlen < 4 as libc::c_int as libc::c_uint {
                                            r = sshpkt_disconnect(
                                                ssh,
                                                b"Corrupted padlen %d on input.\0" as *const u8
                                                    as *const libc::c_char,
                                                padlen,
                                            );
                                            if r != 0 as libc::c_int || {
                                                r = ssh_packet_write_wait(ssh);
                                                r != 0 as libc::c_int
                                            } {
                                                return r;
                                            }
                                            return -(54 as libc::c_int);
                                        }
                                        r = sshbuf_consume(
                                            (*state).incoming_packet,
                                            (4 as libc::c_int + 1 as libc::c_int) as size_t,
                                        );
                                        if !(r != 0 as libc::c_int || {
                                            r = sshbuf_consume_end(
                                                (*state).incoming_packet,
                                                padlen as size_t,
                                            );
                                            r != 0 as libc::c_int
                                        }) {
                                            if !comp.is_null() && (*comp).enabled != 0 {
                                                crate::sshbuf::sshbuf_reset(
                                                    (*state).compression_buffer,
                                                );
                                                r = uncompress_buffer(
                                                    ssh,
                                                    (*state).incoming_packet,
                                                    (*state).compression_buffer,
                                                );
                                                if r != 0 as libc::c_int {
                                                    current_block = 11636842938881510489;
                                                } else {
                                                    crate::sshbuf::sshbuf_reset(
                                                        (*state).incoming_packet,
                                                    );
                                                    r = sshbuf_putb(
                                                        (*state).incoming_packet,
                                                        (*state).compression_buffer,
                                                    );
                                                    if r != 0 as libc::c_int {
                                                        current_block = 11636842938881510489;
                                                    } else {
                                                        current_block = 6367734732029634840;
                                                    }
                                                }
                                            } else {
                                                current_block = 6367734732029634840;
                                            }
                                            match current_block {
                                                11636842938881510489 => {}
                                                _ => {
                                                    r = crate::sshbuf_getput_basic::sshbuf_get_u8(
                                                        (*state).incoming_packet,
                                                        typep,
                                                    );
                                                    if !(r != 0 as libc::c_int) {
                                                        if ssh_packet_log_type(*typep) != 0 {
                                                            crate::log::sshlog(
                                                                b"packet.c\0" as *const u8
                                                                    as *const libc::c_char,
                                                                (*::core::mem::transmute::<
                                                                    &[u8; 22],
                                                                    &[libc::c_char; 22],
                                                                >(
                                                                    b"ssh_packet_read_poll2\0"
                                                                ))
                                                                .as_ptr(),
                                                                1677 as libc::c_int,
                                                                0 as libc::c_int,
                                                                SYSLOG_LEVEL_DEBUG3,
                                                                0 as *const libc::c_char,
                                                                b"receive packet: type %u\0"
                                                                    as *const u8
                                                                    as *const libc::c_char,
                                                                *typep as libc::c_int,
                                                            );
                                                        }
                                                        if (*typep as libc::c_int)
                                                            < 1 as libc::c_int
                                                            || *typep as libc::c_int
                                                                >= 192 as libc::c_int
                                                        {
                                                            r = sshpkt_disconnect(
                                                                ssh,
                                                                b"Invalid ssh2 packet type: %d\0"
                                                                    as *const u8
                                                                    as *const libc::c_char,
                                                                *typep as libc::c_int,
                                                            );
                                                            if r != 0 as libc::c_int || {
                                                                r = ssh_packet_write_wait(ssh);
                                                                r != 0 as libc::c_int
                                                            } {
                                                                return r;
                                                            }
                                                            return -(55 as libc::c_int);
                                                        }
                                                        if ((*state).hook_in).is_some() && {
                                                            r = ((*state).hook_in).expect(
                                                                "non-null function pointer",
                                                            )(
                                                                ssh,
                                                                (*state).incoming_packet,
                                                                typep,
                                                                (*state).hook_in_ctx,
                                                            );
                                                            r != 0 as libc::c_int
                                                        } {
                                                            return r;
                                                        }
                                                        if *typep as libc::c_int
                                                            == 52 as libc::c_int
                                                            && (*state).server_side == 0
                                                        {
                                                            r = ssh_packet_enable_delayed_compress(
                                                                ssh,
                                                            );
                                                        } else {
                                                            r = 0 as libc::c_int;
                                                        }
                                                        (*state).packlen =
                                                            0 as libc::c_int as u_int;
                                                        r = ssh_packet_check_rekey(ssh);
                                                        if r != 0 as libc::c_int {
                                                            return r;
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
                }
            }
        }
        _ => {}
    }
    return r;
}
pub unsafe extern "C" fn ssh_packet_read_poll_seqnr(
    mut ssh: *mut ssh,
    mut typep: *mut u_char,
    mut seqnr_p: *mut u_int32_t,
) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut reason: u_int = 0;
    let mut seqnr: u_int = 0;
    let mut r: libc::c_int = 0;
    let mut msg: *mut u_char = 0 as *mut u_char;
    loop {
        msg = 0 as *mut u_char;
        r = ssh_packet_read_poll2(ssh, typep, seqnr_p);
        if r != 0 as libc::c_int {
            return r;
        }
        if *typep != 0 {
            (*state).keep_alive_timeouts = 0 as libc::c_int;
        }
        match *typep as libc::c_int {
            2 => {
                crate::log::sshlog(
                    b"packet.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"ssh_packet_read_poll_seqnr\0",
                    ))
                    .as_ptr(),
                    1725 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG3,
                    0 as *const libc::c_char,
                    b"Received SSH2_MSG_IGNORE\0" as *const u8 as *const libc::c_char,
                );
            }
            4 => {
                r = sshpkt_get_u8(ssh, 0 as *mut u_char);
                if r != 0 as libc::c_int
                    || {
                        r = sshpkt_get_string(ssh, &mut msg, 0 as *mut size_t);
                        r != 0 as libc::c_int
                    }
                    || {
                        r = sshpkt_get_string(ssh, 0 as *mut *mut u_char, 0 as *mut size_t);
                        r != 0 as libc::c_int
                    }
                {
                    libc::free(msg as *mut libc::c_void);
                    return r;
                }
                crate::log::sshlog(
                    b"packet.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"ssh_packet_read_poll_seqnr\0",
                    ))
                    .as_ptr(),
                    1734 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"Remote: %.900s\0" as *const u8 as *const libc::c_char,
                    msg,
                );
                libc::free(msg as *mut libc::c_void);
            }
            1 => {
                r = sshpkt_get_u32(ssh, &mut reason);
                if r != 0 as libc::c_int || {
                    r = sshpkt_get_string(ssh, &mut msg, 0 as *mut size_t);
                    r != 0 as libc::c_int
                } {
                    return r;
                }
                crate::log::sshlog(
                    b"packet.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"ssh_packet_read_poll_seqnr\0",
                    ))
                    .as_ptr(),
                    1747 as libc::c_int,
                    0 as libc::c_int,
                    (if (*(*ssh).state).server_side != 0
                        && reason == 11 as libc::c_int as libc::c_uint
                    {
                        SYSLOG_LEVEL_INFO as libc::c_int
                    } else {
                        SYSLOG_LEVEL_ERROR as libc::c_int
                    }) as LogLevel,
                    0 as *const libc::c_char,
                    b"Received disconnect from %s port %d:%u: %.400s\0" as *const u8
                        as *const libc::c_char,
                    ssh_remote_ipaddr(ssh),
                    ssh_remote_port(ssh),
                    reason,
                    msg,
                );
                libc::free(msg as *mut libc::c_void);
                return -(29 as libc::c_int);
            }
            3 => {
                r = sshpkt_get_u32(ssh, &mut seqnr);
                if r != 0 as libc::c_int {
                    return r;
                }
                crate::log::sshlog(
                    b"packet.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                        b"ssh_packet_read_poll_seqnr\0",
                    ))
                    .as_ptr(),
                    1754 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"Received SSH2_MSG_UNIMPLEMENTED for %u\0" as *const u8 as *const libc::c_char,
                    seqnr,
                );
            }
            _ => return 0 as libc::c_int,
        }
    }
}
pub unsafe extern "C" fn ssh_packet_process_incoming(
    mut ssh: *mut ssh,
    mut buf: *const libc::c_char,
    mut len: u_int,
) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut r: libc::c_int = 0;
    if (*state).packet_discard != 0 {
        (*state).keep_alive_timeouts = 0 as libc::c_int;
        if len >= (*state).packet_discard {
            r = ssh_packet_stop_discard(ssh);
            if r != 0 as libc::c_int {
                return r;
            }
        }
        (*state).packet_discard =
            ((*state).packet_discard as libc::c_uint).wrapping_sub(len) as u_int as u_int;
        return 0 as libc::c_int;
    }
    r = sshbuf_put((*state).input, buf as *const libc::c_void, len as size_t);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_process_read(
    mut ssh: *mut ssh,
    mut fd: libc::c_int,
) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut r: libc::c_int = 0;
    let mut rlen: size_t = 0;
    r = sshbuf_read(
        fd,
        (*state).input,
        (256 as libc::c_int * 1024 as libc::c_int) as size_t,
        &mut rlen,
    );
    if r != 0 as libc::c_int {
        return r;
    }
    if (*state).packet_discard != 0 {
        r = sshbuf_consume_end((*state).input, rlen);
        if r != 0 as libc::c_int {
            return r;
        }
        (*state).keep_alive_timeouts = 0 as libc::c_int;
        if rlen >= (*state).packet_discard as libc::c_ulong {
            r = ssh_packet_stop_discard(ssh);
            if r != 0 as libc::c_int {
                return r;
            }
        }
        (*state).packet_discard =
            ((*state).packet_discard as libc::c_ulong).wrapping_sub(rlen) as u_int as u_int;
        return 0 as libc::c_int;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_remaining(mut ssh: *mut ssh) -> libc::c_int {
    return crate::sshbuf::sshbuf_len((*(*ssh).state).incoming_packet) as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_send_debug(
    mut ssh: *mut ssh,
    mut fmt: *const libc::c_char,
    mut args: ...
) {
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut args_0: ::core::ffi::VaListImpl;
    let mut r: libc::c_int = 0;
    if (*ssh).compat & 0x40 as libc::c_int != 0 {
        return;
    }
    args_0 = args.clone();
    vsnprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        fmt,
        args_0.as_va_list(),
    );
    crate::log::sshlog(
        b"packet.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"ssh_packet_send_debug\0"))
            .as_ptr(),
        1840 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"sending debug message: %s\0" as *const u8 as *const libc::c_char,
        buf.as_mut_ptr(),
    );
    r = sshpkt_start(ssh, 4 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_u8(ssh, 0 as libc::c_int as u_char);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_cstring(ssh, buf.as_mut_ptr() as *const libc::c_void);
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
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"ssh_packet_send_debug\0"))
                .as_ptr(),
            1848 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"send DEBUG\0" as *const u8 as *const libc::c_char,
        );
    }
}
pub unsafe extern "C" fn sshpkt_fmt_connection_id(
    mut ssh: *mut ssh,
    mut s: *mut libc::c_char,
    mut l: size_t,
) {
    libc::snprintf(
        s,
        l as usize,
        b"%.200s%s%s port %d\0" as *const u8 as *const libc::c_char,
        if !((*ssh).log_preamble).is_null() {
            (*ssh).log_preamble as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*ssh).log_preamble).is_null() {
            b" \0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        ssh_remote_ipaddr(ssh),
        ssh_remote_port(ssh),
    );
}
unsafe extern "C" fn sshpkt_vfatal(
    mut ssh: *mut ssh,
    mut r: libc::c_int,
    mut fmt: *const libc::c_char,
    mut ap: ::core::ffi::VaList,
) {
    let mut tag: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut remote_id: [libc::c_char; 512] = [0; 512];
    let mut oerrno: libc::c_int = *libc::__errno_location();
    sshpkt_fmt_connection_id(
        ssh,
        remote_id.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
    );
    let mut current_block_22: u64;
    match r {
        -52 => {
            ssh_packet_clear_keys(ssh);
            sshlogdie(
                b"packet.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"sshpkt_vfatal\0"))
                    .as_ptr(),
                1874 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Connection closed by %s\0" as *const u8 as *const libc::c_char,
                remote_id.as_mut_ptr(),
            );
        }
        -53 => {
            ssh_packet_clear_keys(ssh);
            sshlogdie(
                b"packet.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"sshpkt_vfatal\0"))
                    .as_ptr(),
                1878 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Connection %s %s timed out\0" as *const u8 as *const libc::c_char,
                if (*(*ssh).state).server_side != 0 {
                    b"from\0" as *const u8 as *const libc::c_char
                } else {
                    b"to\0" as *const u8 as *const libc::c_char
                },
                remote_id.as_mut_ptr(),
            );
        }
        -29 => {
            ssh_packet_clear_keys(ssh);
            sshlogdie(
                b"packet.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"sshpkt_vfatal\0"))
                    .as_ptr(),
                1881 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Disconnected from %s\0" as *const u8 as *const libc::c_char,
                remote_id.as_mut_ptr(),
            );
        }
        -24 => {
            if *libc::__errno_location() == 104 as libc::c_int {
                ssh_packet_clear_keys(ssh);
                sshlogdie(
                    b"packet.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"sshpkt_vfatal\0"))
                        .as_ptr(),
                    1885 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Connection reset by %s\0" as *const u8 as *const libc::c_char,
                    remote_id.as_mut_ptr(),
                );
            }
            current_block_22 = 1402817794221548365;
        }
        -31 | -32 | -33 | -34 | -35 => {
            current_block_22 = 1402817794221548365;
        }
        _ => {
            current_block_22 = 9578114137596928991;
        }
    }
    match current_block_22 {
        1402817794221548365 => {
            if !((*ssh).kex).is_null() && !((*(*ssh).kex).failed_choice).is_null() {
                ssh_packet_clear_keys(ssh);
                *libc::__errno_location() = oerrno;
                sshlogdie(
                    b"packet.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"sshpkt_vfatal\0"))
                        .as_ptr(),
                    1898 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"Unable to negotiate with %s: %s. Their offer: %s\0" as *const u8
                        as *const libc::c_char,
                    remote_id.as_mut_ptr(),
                    ssh_err(r),
                    (*(*ssh).kex).failed_choice,
                );
            }
        }
        _ => {}
    }
    if vasprintf(&mut tag, fmt, ap.as_va_list()) == -(1 as libc::c_int) {
        ssh_packet_clear_keys(ssh);
        sshlogdie(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"sshpkt_vfatal\0"))
                .as_ptr(),
            1904 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"could not allocate failure message\0" as *const u8 as *const libc::c_char,
        );
    }
    ssh_packet_clear_keys(ssh);
    *libc::__errno_location() = oerrno;
    sshlogdie(
        b"packet.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"sshpkt_vfatal\0")).as_ptr(),
        1910 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        ssh_err(r),
        b"%s%sConnection %s %s\0" as *const u8 as *const libc::c_char,
        if !tag.is_null() {
            tag as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !tag.is_null() {
            b": \0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if (*(*ssh).state).server_side != 0 {
            b"from\0" as *const u8 as *const libc::c_char
        } else {
            b"to\0" as *const u8 as *const libc::c_char
        },
        remote_id.as_mut_ptr(),
    );
}
pub unsafe extern "C" fn sshpkt_fatal(
    mut ssh: *mut ssh,
    mut r: libc::c_int,
    mut fmt: *const libc::c_char,
    mut args: ...
) -> ! {
    let mut ap: ::core::ffi::VaListImpl;
    ap = args.clone();
    sshpkt_vfatal(ssh, r, fmt, ap.as_va_list());
    sshlogdie(
        b"packet.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"sshpkt_fatal\0")).as_ptr(),
        1923 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"should have exited\0" as *const u8 as *const libc::c_char,
    );
}
pub unsafe extern "C" fn ssh_packet_disconnect(
    mut ssh: *mut ssh,
    mut fmt: *const libc::c_char,
    mut args: ...
) -> ! {
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut remote_id: [libc::c_char; 512] = [0; 512];
    let mut args_0: ::core::ffi::VaListImpl;
    static mut disconnecting: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    if disconnecting != 0 {
        sshfatal(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"ssh_packet_disconnect\0"))
                .as_ptr(),
            1941 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"packet_disconnect called recursively.\0" as *const u8 as *const libc::c_char,
        );
    }
    disconnecting = 1 as libc::c_int;
    sshpkt_fmt_connection_id(
        ssh,
        remote_id.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
    );
    args_0 = args.clone();
    vsnprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        fmt,
        args_0.as_va_list(),
    );
    crate::log::sshlog(
        b"packet.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"ssh_packet_disconnect\0"))
            .as_ptr(),
        1954 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_INFO,
        0 as *const libc::c_char,
        b"Disconnecting %s: %.100s\0" as *const u8 as *const libc::c_char,
        remote_id.as_mut_ptr(),
        buf.as_mut_ptr(),
    );
    r = sshpkt_disconnect(
        ssh,
        b"%s\0" as *const u8 as *const libc::c_char,
        buf.as_mut_ptr(),
    );
    if r != 0 as libc::c_int {
        sshpkt_fatal(
            ssh,
            r,
            b"%s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"ssh_packet_disconnect\0"))
                .as_ptr(),
        );
    }
    r = ssh_packet_write_wait(ssh);
    if r != 0 as libc::c_int {
        sshpkt_fatal(
            ssh,
            r,
            b"%s\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"ssh_packet_disconnect\0"))
                .as_ptr(),
        );
    }
    ssh_packet_close(ssh);
    cleanup_exit(255 as libc::c_int);
}
pub unsafe extern "C" fn ssh_packet_write_poll(mut ssh: *mut ssh) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut len: libc::c_int = crate::sshbuf::sshbuf_len((*state).output) as libc::c_int;
    let mut r: libc::c_int = 0;
    if len > 0 as libc::c_int {
        len = write(
            (*state).connection_out,
            sshbuf_ptr((*state).output) as *const libc::c_void,
            len as size_t,
        ) as libc::c_int;
        if len == -(1 as libc::c_int) {
            if *libc::__errno_location() == 4 as libc::c_int
                || *libc::__errno_location() == 11 as libc::c_int
                || *libc::__errno_location() == 11 as libc::c_int
            {
                return 0 as libc::c_int;
            }
            return -(24 as libc::c_int);
        }
        if len == 0 as libc::c_int {
            return -(52 as libc::c_int);
        }
        r = sshbuf_consume((*state).output, len as size_t);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_write_wait(mut ssh: *mut ssh) -> libc::c_int {
    let mut ret: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut ms_remain: libc::c_int = 0 as libc::c_int;
    let mut start: libc::timeval = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut timespec: libc::timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let mut timespecp: *mut libc::timespec = 0 as *mut libc::timespec;
    let mut state: *mut session_state = (*ssh).state;
    let mut pfd: pollfd = pollfd {
        fd: 0,
        events: 0,
        revents: 0,
    };
    r = ssh_packet_write_poll(ssh);
    if r != 0 as libc::c_int {
        return r;
    }
    while ssh_packet_have_data_to_write(ssh) != 0 {
        pfd.fd = (*state).connection_out;
        pfd.events = 0x4 as libc::c_int as libc::c_short;
        if (*state).packet_timeout_ms > 0 as libc::c_int {
            ms_remain = (*state).packet_timeout_ms;
            timespecp = &mut timespec;
        }
        loop {
            if (*state).packet_timeout_ms > 0 as libc::c_int {
                ms_to_timespec(&mut timespec, ms_remain);
                monotime_tv(&mut start);
            }
            ret = ppoll(
                &mut pfd,
                1 as libc::c_int as nfds_t,
                timespecp,
                0 as *const __sigset_t,
            );
            if ret >= 0 as libc::c_int {
                break;
            }
            if *libc::__errno_location() != 11 as libc::c_int
                && *libc::__errno_location() != 4 as libc::c_int
                && *libc::__errno_location() != 11 as libc::c_int
            {
                break;
            }
            if (*state).packet_timeout_ms <= 0 as libc::c_int {
                continue;
            }
            ms_subtract_diff(&mut start, &mut ms_remain);
            if !(ms_remain <= 0 as libc::c_int) {
                continue;
            }
            ret = 0 as libc::c_int;
            break;
        }
        if ret == 0 as libc::c_int {
            return -(53 as libc::c_int);
        }
        r = ssh_packet_write_poll(ssh);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_have_data_to_write(mut ssh: *mut ssh) -> libc::c_int {
    return (crate::sshbuf::sshbuf_len((*(*ssh).state).output) != 0 as libc::c_int as libc::c_ulong)
        as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_not_very_much_data_to_write(mut ssh: *mut ssh) -> libc::c_int {
    if (*(*ssh).state).interactive_mode != 0 {
        return (crate::sshbuf::sshbuf_len((*(*ssh).state).output)
            < 16384 as libc::c_int as libc::c_ulong) as libc::c_int;
    } else {
        return (crate::sshbuf::sshbuf_len((*(*ssh).state).output)
            < (128 as libc::c_int * 1024 as libc::c_int) as libc::c_ulong)
            as libc::c_int;
    };
}
pub unsafe extern "C" fn ssh_packet_set_tos(mut ssh: *mut ssh, mut tos: libc::c_int) {
    if ssh_packet_connection_is_on_socket(ssh) == 0 || tos == 2147483647 as libc::c_int {
        return;
    }
    set_sock_tos((*(*ssh).state).connection_in, tos);
}
pub unsafe extern "C" fn ssh_packet_set_interactive(
    mut ssh: *mut ssh,
    mut interactive: libc::c_int,
    mut qos_interactive: libc::c_int,
    mut qos_bulk: libc::c_int,
) {
    let mut state: *mut session_state = (*ssh).state;
    if (*state).set_interactive_called != 0 {
        return;
    }
    (*state).set_interactive_called = 1 as libc::c_int;
    (*state).interactive_mode = interactive;
    if ssh_packet_connection_is_on_socket(ssh) == 0 {
        return;
    }
    set_nodelay((*state).connection_in);
    ssh_packet_set_tos(
        ssh,
        if interactive != 0 {
            qos_interactive
        } else {
            qos_bulk
        },
    );
}
pub unsafe extern "C" fn ssh_packet_is_interactive(mut ssh: *mut ssh) -> libc::c_int {
    return (*(*ssh).state).interactive_mode;
}
pub unsafe extern "C" fn ssh_packet_set_maxsize(mut ssh: *mut ssh, mut s: u_int) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    if (*state).set_maxsize_called != 0 {
        crate::log::sshlog(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"ssh_packet_set_maxsize\0",
            ))
            .as_ptr(),
            2111 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"called twice: old %d new %d\0" as *const u8 as *const libc::c_char,
            (*state).max_packet_size,
            s,
        );
        return -(1 as libc::c_int);
    }
    if s < (4 as libc::c_int * 1024 as libc::c_int) as libc::c_uint
        || s > (1024 as libc::c_int * 1024 as libc::c_int) as libc::c_uint
    {
        crate::log::sshlog(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"ssh_packet_set_maxsize\0",
            ))
            .as_ptr(),
            2115 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"bad size %d\0" as *const u8 as *const libc::c_char,
            s,
        );
        return -(1 as libc::c_int);
    }
    (*state).set_maxsize_called = 1 as libc::c_int;
    crate::log::sshlog(
        b"packet.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(b"ssh_packet_set_maxsize\0"))
            .as_ptr(),
        2119 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"setting to %d\0" as *const u8 as *const libc::c_char,
        s,
    );
    (*state).max_packet_size = s;
    return s as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_inc_alive_timeouts(mut ssh: *mut ssh) -> libc::c_int {
    (*(*ssh).state).keep_alive_timeouts += 1;
    return (*(*ssh).state).keep_alive_timeouts;
}
pub unsafe extern "C" fn ssh_packet_set_alive_timeouts(mut ssh: *mut ssh, mut ka: libc::c_int) {
    (*(*ssh).state).keep_alive_timeouts = ka;
}
pub unsafe extern "C" fn ssh_packet_get_maxsize(mut ssh: *mut ssh) -> u_int {
    return (*(*ssh).state).max_packet_size;
}
pub unsafe extern "C" fn ssh_packet_set_rekey_limits(
    mut ssh: *mut ssh,
    mut bytes: u_int64_t,
    mut seconds: u_int32_t,
) {
    crate::log::sshlog(
        b"packet.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
            b"ssh_packet_set_rekey_limits\0",
        ))
        .as_ptr(),
        2146 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"rekey after %llu bytes, %u seconds\0" as *const u8 as *const libc::c_char,
        bytes as libc::c_ulonglong,
        seconds,
    );
    (*(*ssh).state).rekey_limit = bytes;
    (*(*ssh).state).rekey_interval = seconds;
}
pub unsafe extern "C" fn ssh_packet_get_rekey_timeout(mut ssh: *mut ssh) -> time_t {
    let mut seconds: time_t = 0;
    seconds =
        (*(*ssh).state).rekey_time + (*(*ssh).state).rekey_interval as libc::c_long - monotime();
    return if seconds <= 0 as libc::c_int as libc::c_long {
        1 as libc::c_int as libc::c_long
    } else {
        seconds
    };
}
pub unsafe extern "C" fn ssh_packet_set_server(mut ssh: *mut ssh) {
    (*(*ssh).state).server_side = 1 as libc::c_int;
    (*(*ssh).kex).server = 1 as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_set_authenticated(mut ssh: *mut ssh) {
    (*(*ssh).state).after_authentication = 1 as libc::c_int;
}
pub unsafe extern "C" fn ssh_packet_get_input(mut ssh: *mut ssh) -> *mut libc::c_void {
    return (*(*ssh).state).input as *mut libc::c_void;
}
pub unsafe extern "C" fn ssh_packet_get_output(mut ssh: *mut ssh) -> *mut libc::c_void {
    return (*(*ssh).state).output as *mut libc::c_void;
}
unsafe extern "C" fn ssh_packet_set_postauth(mut ssh: *mut ssh) -> libc::c_int {
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"packet.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"ssh_packet_set_postauth\0"))
            .as_ptr(),
        2192 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"called\0" as *const u8 as *const libc::c_char,
    );
    (*(*ssh).state).after_authentication = 1 as libc::c_int;
    (*(*ssh).state).rekeying = 0 as libc::c_int;
    r = ssh_packet_enable_delayed_compress(ssh);
    if r != 0 as libc::c_int {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn kex_to_blob(
    mut m: *mut crate::sshbuf::sshbuf,
    mut kex: *mut kex,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, (*kex).we_need);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_put_cstring(m, (*kex).hostkey_alg);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, (*kex).hostkey_type as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, (*kex).hostkey_nid as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, (*kex).kex_type);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(m, (*kex).my);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(m, (*kex).peer);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(m, (*kex).client_version);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(m, (*kex).server_version);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(m, (*kex).session_id);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, (*kex).flags);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn newkeys_to_blob(
    mut m: *mut crate::sshbuf::sshbuf,
    mut ssh: *mut ssh,
    mut mode: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut cc: *mut sshcipher_ctx = 0 as *mut sshcipher_ctx;
    let mut comp: *mut sshcomp = 0 as *mut sshcomp;
    let mut enc: *mut sshenc = 0 as *mut sshenc;
    let mut mac: *mut sshmac = 0 as *mut sshmac;
    let mut newkey: *mut newkeys = 0 as *mut newkeys;
    let mut r: libc::c_int = 0;
    newkey = (*(*ssh).state).newkeys[mode as usize];
    if newkey.is_null() {
        return -(1 as libc::c_int);
    }
    enc = &mut (*newkey).enc;
    mac = &mut (*newkey).mac;
    comp = &mut (*newkey).comp;
    cc = if mode == MODE_OUT as libc::c_int {
        (*(*ssh).state).send_context
    } else {
        (*(*ssh).state).receive_context
    };
    r = cipher_get_keyiv(cc, (*enc).iv, (*enc).iv_len as size_t);
    if r != 0 as libc::c_int {
        return r;
    }
    b = crate::sshbuf::sshbuf_new();
    if b.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_put_cstring(b, (*enc).name);
    if !(r != 0 as libc::c_int
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u32(b, (*enc).enabled as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u32(b, (*enc).block_size);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(
                b,
                (*enc).key as *const libc::c_void,
                (*enc).key_len as size_t,
            );
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(b, (*enc).iv as *const libc::c_void, (*enc).iv_len as size_t);
            r != 0 as libc::c_int
        })
    {
        if cipher_authlen((*enc).cipher) == 0 as libc::c_int as libc::c_uint {
            r = sshbuf_put_cstring(b, (*mac).name);
            if r != 0 as libc::c_int
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_put_u32(b, (*mac).enabled as u_int32_t);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_string(
                        b,
                        (*mac).key as *const libc::c_void,
                        (*mac).key_len as size_t,
                    );
                    r != 0 as libc::c_int
                }
            {
                current_block = 14301505990650711411;
            } else {
                current_block = 1856101646708284338;
            }
        } else {
            current_block = 1856101646708284338;
        }
        match current_block {
            14301505990650711411 => {}
            _ => {
                r = crate::sshbuf_getput_basic::sshbuf_put_u32(b, (*comp).type_0);
                if !(r != 0 as libc::c_int || {
                    r = sshbuf_put_cstring(b, (*comp).name);
                    r != 0 as libc::c_int
                }) {
                    r = sshbuf_put_stringb(m, b);
                }
            }
        }
    }
    crate::sshbuf::sshbuf_free(b);
    return r;
}
pub unsafe extern "C" fn ssh_packet_get_state(
    mut ssh: *mut ssh,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut r: libc::c_int = 0;
    r = kex_to_blob(m, (*ssh).kex);
    if r != 0 as libc::c_int
        || {
            r = newkeys_to_blob(m, ssh, MODE_OUT as libc::c_int);
            r != 0 as libc::c_int
        }
        || {
            r = newkeys_to_blob(m, ssh, MODE_IN as libc::c_int);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u64(m, (*state).rekey_limit);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, (*state).rekey_interval);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, (*state).p_send.seqnr);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u64(m, (*state).p_send.blocks);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, (*state).p_send.packets);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u64(m, (*state).p_send.bytes);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, (*state).p_read.seqnr);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u64(m, (*state).p_read.blocks);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u32(m, (*state).p_read.packets);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_put_u64(m, (*state).p_read.bytes);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(m, (*state).input);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_stringb(m, (*state).output);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn newkeys_from_blob(
    mut m: *mut crate::sshbuf::sshbuf,
    mut ssh: *mut ssh,
    mut mode: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut b: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut comp: *mut sshcomp = 0 as *mut sshcomp;
    let mut enc: *mut sshenc = 0 as *mut sshenc;
    let mut mac: *mut sshmac = 0 as *mut sshmac;
    let mut newkey: *mut newkeys = 0 as *mut newkeys;
    let mut keylen: size_t = 0;
    let mut ivlen: size_t = 0;
    let mut maclen: size_t = 0;
    let mut r: libc::c_int = 0;
    newkey = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<newkeys>() as libc::c_ulong,
    ) as *mut newkeys;
    if newkey.is_null() {
        r = -(2 as libc::c_int);
    } else {
        r = sshbuf_froms(m, &mut b);
        if !(r != 0 as libc::c_int) {
            enc = &mut (*newkey).enc;
            mac = &mut (*newkey).mac;
            comp = &mut (*newkey).comp;
            r = sshbuf_get_cstring(b, &mut (*enc).name, 0 as *mut size_t);
            if !(r != 0 as libc::c_int
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_get_u32(
                        b,
                        &mut (*enc).enabled as *mut libc::c_int as *mut u_int,
                    );
                    r != 0 as libc::c_int
                }
                || {
                    r = crate::sshbuf_getput_basic::sshbuf_get_u32(b, &mut (*enc).block_size);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_get_string(b, &mut (*enc).key, &mut keylen);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_get_string(b, &mut (*enc).iv, &mut ivlen);
                    r != 0 as libc::c_int
                })
            {
                (*enc).cipher = cipher_by_name((*enc).name);
                if ((*enc).cipher).is_null() {
                    r = -(4 as libc::c_int);
                } else {
                    if cipher_authlen((*enc).cipher) == 0 as libc::c_int as libc::c_uint {
                        r = sshbuf_get_cstring(b, &mut (*mac).name, 0 as *mut size_t);
                        if r != 0 as libc::c_int {
                            current_block = 15195334471293752841;
                        } else {
                            r = mac_setup(mac, (*mac).name);
                            if r != 0 as libc::c_int {
                                current_block = 15195334471293752841;
                            } else {
                                r = crate::sshbuf_getput_basic::sshbuf_get_u32(
                                    b,
                                    &mut (*mac).enabled as *mut libc::c_int as *mut u_int,
                                );
                                if r != 0 as libc::c_int || {
                                    r = sshbuf_get_string(b, &mut (*mac).key, &mut maclen);
                                    r != 0 as libc::c_int
                                } {
                                    current_block = 15195334471293752841;
                                } else if maclen > (*mac).key_len as libc::c_ulong {
                                    r = -(4 as libc::c_int);
                                    current_block = 15195334471293752841;
                                } else {
                                    (*mac).key_len = maclen as u_int;
                                    current_block = 15652330335145281839;
                                }
                            }
                        }
                    } else {
                        current_block = 15652330335145281839;
                    }
                    match current_block {
                        15195334471293752841 => {}
                        _ => {
                            r = crate::sshbuf_getput_basic::sshbuf_get_u32(b, &mut (*comp).type_0);
                            if !(r != 0 as libc::c_int || {
                                r = sshbuf_get_cstring(b, &mut (*comp).name, 0 as *mut size_t);
                                r != 0 as libc::c_int
                            }) {
                                if crate::sshbuf::sshbuf_len(b) != 0 as libc::c_int as libc::c_ulong
                                {
                                    r = -(4 as libc::c_int);
                                } else {
                                    (*enc).key_len = keylen as u_int;
                                    (*enc).iv_len = ivlen as u_int;
                                    (*(*ssh).kex).newkeys[mode as usize] = newkey;
                                    newkey = 0 as *mut newkeys;
                                    r = 0 as libc::c_int;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    libc::free(newkey as *mut libc::c_void);
    crate::sshbuf::sshbuf_free(b);
    return r;
}
unsafe extern "C" fn kex_from_blob(
    mut m: *mut crate::sshbuf::sshbuf,
    mut kexp: *mut *mut kex,
) -> libc::c_int {
    let mut kex: *mut kex = 0 as *mut kex;
    let mut r: libc::c_int = 0;
    kex = kex_new();
    if kex.is_null() {
        return -(2 as libc::c_int);
    }
    r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut (*kex).we_need);
    if !(r != 0 as libc::c_int
        || {
            r = sshbuf_get_cstring(m, &mut (*kex).hostkey_alg, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(
                m,
                &mut (*kex).hostkey_type as *mut libc::c_int as *mut u_int,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(
                m,
                &mut (*kex).hostkey_nid as *mut libc::c_int as *mut u_int,
            );
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut (*kex).kex_type);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_stringb(m, (*kex).my);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_stringb(m, (*kex).peer);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_stringb(m, (*kex).client_version);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_stringb(m, (*kex).server_version);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_stringb(m, (*kex).session_id);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut (*kex).flags);
            r != 0 as libc::c_int
        })
    {
        (*kex).server = 1 as libc::c_int;
        (*kex).done = 1 as libc::c_int;
        r = 0 as libc::c_int;
    }
    if r != 0 as libc::c_int || kexp.is_null() {
        kex_free(kex);
        if !kexp.is_null() {
            *kexp = 0 as *mut kex;
        }
    } else {
        kex_free(*kexp);
        *kexp = kex;
    }
    return r;
}
pub unsafe extern "C" fn ssh_packet_set_state(
    mut ssh: *mut ssh,
    mut m: *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut input: *const u_char = 0 as *const u_char;
    let mut output: *const u_char = 0 as *const u_char;
    let mut ilen: size_t = 0;
    let mut olen: size_t = 0;
    let mut r: libc::c_int = 0;
    r = kex_from_blob(m, &mut (*ssh).kex);
    if r != 0 as libc::c_int
        || {
            r = newkeys_from_blob(m, ssh, MODE_OUT as libc::c_int);
            r != 0 as libc::c_int
        }
        || {
            r = newkeys_from_blob(m, ssh, MODE_IN as libc::c_int);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u64(m, &mut (*state).rekey_limit);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut (*state).rekey_interval);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut (*state).p_send.seqnr);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u64(m, &mut (*state).p_send.blocks);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut (*state).p_send.packets);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u64(m, &mut (*state).p_send.bytes);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut (*state).p_read.seqnr);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u64(m, &mut (*state).p_read.blocks);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u32(m, &mut (*state).p_read.packets);
            r != 0 as libc::c_int
        }
        || {
            r = crate::sshbuf_getput_basic::sshbuf_get_u64(m, &mut (*state).p_read.bytes);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    (*state).rekey_time = monotime();
    r = ssh_set_newkeys(ssh, MODE_IN as libc::c_int);
    if r != 0 as libc::c_int || {
        r = ssh_set_newkeys(ssh, MODE_OUT as libc::c_int);
        r != 0 as libc::c_int
    } {
        return r;
    }
    r = ssh_packet_set_postauth(ssh);
    if r != 0 as libc::c_int {
        return r;
    }
    crate::sshbuf::sshbuf_reset((*state).input);
    crate::sshbuf::sshbuf_reset((*state).output);
    r = sshbuf_get_string_direct(m, &mut input, &mut ilen);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_string_direct(m, &mut output, &mut olen);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put((*state).input, input as *const libc::c_void, ilen);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put((*state).output, output as *const libc::c_void, olen);
            r != 0 as libc::c_int
        }
    {
        return r;
    }
    if crate::sshbuf::sshbuf_len(m) != 0 {
        return -(4 as libc::c_int);
    }
    crate::log::sshlog(
        b"packet.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 21], &[libc::c_char; 21]>(b"ssh_packet_set_state\0"))
            .as_ptr(),
        2447 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"done\0" as *const u8 as *const libc::c_char,
    );
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshpkt_put(
    mut ssh: *mut ssh,
    mut v: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    return sshbuf_put((*(*ssh).state).outgoing_packet, v, len);
}
pub unsafe extern "C" fn sshpkt_putb(
    mut ssh: *mut ssh,
    mut b: *const crate::sshbuf::sshbuf,
) -> libc::c_int {
    return sshbuf_putb((*(*ssh).state).outgoing_packet, b);
}
pub unsafe extern "C" fn sshpkt_put_u8(mut ssh: *mut ssh, mut val: u_char) -> libc::c_int {
    return crate::sshbuf_getput_basic::sshbuf_put_u8((*(*ssh).state).outgoing_packet, val);
}
pub unsafe extern "C" fn sshpkt_put_u32(mut ssh: *mut ssh, mut val: u_int32_t) -> libc::c_int {
    return crate::sshbuf_getput_basic::sshbuf_put_u32((*(*ssh).state).outgoing_packet, val);
}
pub unsafe extern "C" fn sshpkt_put_u64(mut ssh: *mut ssh, mut val: u_int64_t) -> libc::c_int {
    return crate::sshbuf_getput_basic::sshbuf_put_u64((*(*ssh).state).outgoing_packet, val);
}
pub unsafe extern "C" fn sshpkt_put_string(
    mut ssh: *mut ssh,
    mut v: *const libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    return sshbuf_put_string((*(*ssh).state).outgoing_packet, v, len);
}
pub unsafe extern "C" fn sshpkt_put_cstring(
    mut ssh: *mut ssh,
    mut v: *const libc::c_void,
) -> libc::c_int {
    return sshbuf_put_cstring((*(*ssh).state).outgoing_packet, v as *const libc::c_char);
}
pub unsafe extern "C" fn sshpkt_put_stringb(
    mut ssh: *mut ssh,
    mut v: *const crate::sshbuf::sshbuf,
) -> libc::c_int {
    return sshbuf_put_stringb((*(*ssh).state).outgoing_packet, v);
}
pub unsafe extern "C" fn sshpkt_getb_froms(
    mut ssh: *mut ssh,
    mut valp: *mut *mut crate::sshbuf::sshbuf,
) -> libc::c_int {
    return sshbuf_froms((*(*ssh).state).incoming_packet, valp);
}
pub unsafe extern "C" fn sshpkt_put_ec(
    mut ssh: *mut ssh,
    mut v: *const EC_POINT,
    mut g: *const EC_GROUP,
) -> libc::c_int {
    return sshbuf_put_ec((*(*ssh).state).outgoing_packet, v, g);
}
pub unsafe extern "C" fn sshpkt_put_bignum2(
    mut ssh: *mut ssh,
    mut v: *const BIGNUM,
) -> libc::c_int {
    return sshbuf_put_bignum2((*(*ssh).state).outgoing_packet, v);
}
pub unsafe extern "C" fn sshpkt_get(
    mut ssh: *mut ssh,
    mut valp: *mut libc::c_void,
    mut len: size_t,
) -> libc::c_int {
    return sshbuf_get((*(*ssh).state).incoming_packet, valp, len);
}
pub unsafe extern "C" fn sshpkt_get_u8(mut ssh: *mut ssh, mut valp: *mut u_char) -> libc::c_int {
    return crate::sshbuf_getput_basic::sshbuf_get_u8((*(*ssh).state).incoming_packet, valp);
}
pub unsafe extern "C" fn sshpkt_get_u32(
    mut ssh: *mut ssh,
    mut valp: *mut u_int32_t,
) -> libc::c_int {
    return crate::sshbuf_getput_basic::sshbuf_get_u32((*(*ssh).state).incoming_packet, valp);
}
pub unsafe extern "C" fn sshpkt_get_u64(
    mut ssh: *mut ssh,
    mut valp: *mut u_int64_t,
) -> libc::c_int {
    return crate::sshbuf_getput_basic::sshbuf_get_u64((*(*ssh).state).incoming_packet, valp);
}
pub unsafe extern "C" fn sshpkt_get_string(
    mut ssh: *mut ssh,
    mut valp: *mut *mut u_char,
    mut lenp: *mut size_t,
) -> libc::c_int {
    return sshbuf_get_string((*(*ssh).state).incoming_packet, valp, lenp);
}
pub unsafe extern "C" fn sshpkt_get_string_direct(
    mut ssh: *mut ssh,
    mut valp: *mut *const u_char,
    mut lenp: *mut size_t,
) -> libc::c_int {
    return sshbuf_get_string_direct((*(*ssh).state).incoming_packet, valp, lenp);
}
pub unsafe extern "C" fn sshpkt_peek_string_direct(
    mut ssh: *mut ssh,
    mut valp: *mut *const u_char,
    mut lenp: *mut size_t,
) -> libc::c_int {
    return sshbuf_peek_string_direct((*(*ssh).state).incoming_packet, valp, lenp);
}
pub unsafe extern "C" fn sshpkt_get_cstring(
    mut ssh: *mut ssh,
    mut valp: *mut *mut libc::c_char,
    mut lenp: *mut size_t,
) -> libc::c_int {
    return sshbuf_get_cstring((*(*ssh).state).incoming_packet, valp, lenp);
}
pub unsafe extern "C" fn sshpkt_get_ec(
    mut ssh: *mut ssh,
    mut v: *mut EC_POINT,
    mut g: *const EC_GROUP,
) -> libc::c_int {
    return sshbuf_get_ec((*(*ssh).state).incoming_packet, v, g);
}
pub unsafe extern "C" fn sshpkt_get_bignum2(
    mut ssh: *mut ssh,
    mut valp: *mut *mut BIGNUM,
) -> libc::c_int {
    return sshbuf_get_bignum2((*(*ssh).state).incoming_packet, valp);
}
pub unsafe extern "C" fn sshpkt_get_end(mut ssh: *mut ssh) -> libc::c_int {
    if crate::sshbuf::sshbuf_len((*(*ssh).state).incoming_packet)
        > 0 as libc::c_int as libc::c_ulong
    {
        return -(23 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshpkt_ptr(mut ssh: *mut ssh, mut lenp: *mut size_t) -> *const u_char {
    if !lenp.is_null() {
        *lenp = crate::sshbuf::sshbuf_len((*(*ssh).state).incoming_packet);
    }
    return sshbuf_ptr((*(*ssh).state).incoming_packet);
}
pub unsafe extern "C" fn sshpkt_start(mut ssh: *mut ssh, mut type_0: u_char) -> libc::c_int {
    let mut buf: [u_char; 6] = [0; 6];
    memset(
        buf.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[u_char; 6]>() as libc::c_ulong,
    );
    buf[(::core::mem::size_of::<[u_char; 6]>() as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize] = type_0;
    crate::sshbuf::sshbuf_reset((*(*ssh).state).outgoing_packet);
    return sshbuf_put(
        (*(*ssh).state).outgoing_packet,
        buf.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[u_char; 6]>() as libc::c_ulong,
    );
}
unsafe extern "C" fn ssh_packet_send_mux(mut ssh: *mut ssh) -> libc::c_int {
    let mut state: *mut session_state = (*ssh).state;
    let mut type_0: u_char = 0;
    let mut cp: *mut u_char = 0 as *mut u_char;
    let mut len: size_t = 0;
    let mut r: libc::c_int = 0;
    if !((*ssh).kex).is_null() {
        return -(1 as libc::c_int);
    }
    len = crate::sshbuf::sshbuf_len((*state).outgoing_packet);
    if len < 6 as libc::c_int as libc::c_ulong {
        return -(1 as libc::c_int);
    }
    cp = sshbuf_mutable_ptr((*state).outgoing_packet);
    type_0 = *cp.offset(5 as libc::c_int as isize);
    if ssh_packet_log_type(type_0) != 0 {
        crate::log::sshlog(
            b"packet.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"ssh_packet_send_mux\0"))
                .as_ptr(),
            2638 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"type %u\0" as *const u8 as *const libc::c_char,
            type_0 as libc::c_int,
        );
    }
    if type_0 as libc::c_int >= 80 as libc::c_int && type_0 as libc::c_int <= 127 as libc::c_int {
        let __v: u_int32_t = len.wrapping_sub(4 as libc::c_int as libc::c_ulong) as u_int32_t;
        *cp.offset(0 as libc::c_int as isize) =
            (__v >> 24 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
        *cp.offset(1 as libc::c_int as isize) =
            (__v >> 16 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
        *cp.offset(2 as libc::c_int as isize) =
            (__v >> 8 as libc::c_int & 0xff as libc::c_int as libc::c_uint) as u_char;
        *cp.offset(3 as libc::c_int as isize) =
            (__v & 0xff as libc::c_int as libc::c_uint) as u_char;
        r = sshbuf_putb((*state).output, (*state).outgoing_packet);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    crate::sshbuf::sshbuf_reset((*state).outgoing_packet);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshpkt_msg_ignore(mut ssh: *mut ssh, mut nbytes: u_int) -> libc::c_int {
    let mut rnd: u_int32_t = 0 as libc::c_int as u_int32_t;
    let mut r: libc::c_int = 0;
    let mut i: u_int = 0;
    r = sshpkt_start(ssh, 2 as libc::c_int as u_char);
    if r != 0 as libc::c_int || {
        r = sshpkt_put_u32(ssh, nbytes);
        r != 0 as libc::c_int
    } {
        return r;
    }
    i = 0 as libc::c_int as u_int;
    while i < nbytes {
        if i.wrapping_rem(4 as libc::c_int as libc::c_uint) == 0 as libc::c_int as libc::c_uint {
            rnd = arc4random();
        }
        r = sshpkt_put_u8(
            ssh,
            (rnd as u_char as libc::c_int & 0xff as libc::c_int) as u_char,
        );
        if r != 0 as libc::c_int {
            return r;
        }
        rnd >>= 8 as libc::c_int;
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshpkt_send(mut ssh: *mut ssh) -> libc::c_int {
    if !((*ssh).state).is_null() && (*(*ssh).state).mux != 0 {
        return ssh_packet_send_mux(ssh);
    }
    return ssh_packet_send2(ssh);
}
pub unsafe extern "C" fn sshpkt_disconnect(
    mut ssh: *mut ssh,
    mut fmt: *const libc::c_char,
    mut args: ...
) -> libc::c_int {
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut args_0: ::core::ffi::VaListImpl;
    let mut r: libc::c_int = 0;
    args_0 = args.clone();
    vsnprintf(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        fmt,
        args_0.as_va_list(),
    );
    r = sshpkt_start(ssh, 1 as libc::c_int as u_char);
    if r != 0 as libc::c_int
        || {
            r = sshpkt_put_u32(ssh, 2 as libc::c_int as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshpkt_put_cstring(ssh, buf.as_mut_ptr() as *const libc::c_void);
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
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshpkt_add_padding(mut ssh: *mut ssh, mut pad: u_char) -> libc::c_int {
    (*(*ssh).state).extra_pad = pad;
    return 0 as libc::c_int;
}
