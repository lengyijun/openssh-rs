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

    pub type ec_group_st;
    pub type dh_st;
    pub type umac_ctx;
    pub type ssh_hmac_ctx;
    pub type sshcipher;
    pub type session_state;
    fn socket(__domain: libc::c_int, __type: libc::c_int, __protocol: libc::c_int) -> libc::c_int;

    fn bind(__fd: libc::c_int, __addr: __CONST_SOCKADDR_ARG, __len: socklen_t) -> libc::c_int;
    fn setsockopt(
        __fd: libc::c_int,
        __level: libc::c_int,
        __optname: libc::c_int,
        __optval: *const libc::c_void,
        __optlen: socklen_t,
    ) -> libc::c_int;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;

    fn pipe(__pipedes: *mut libc::c_int) -> libc::c_int;
    fn sleep(__seconds: libc::c_uint) -> libc::c_uint;
    fn dup(__fd: libc::c_int) -> libc::c_int;

    fn execv(__path: *const libc::c_char, __argv: *const *mut libc::c_char) -> libc::c_int;
    fn execl(__path: *const libc::c_char, __arg: *const libc::c_char, _: ...) -> libc::c_int;

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
    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;

    fn strlcat(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;

    fn fcntl(__fd: libc::c_int, __cmd: libc::c_int, _: ...) -> libc::c_int;

    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;

    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

    fn getifaddrs(__ifap: *mut *mut ifaddrs) -> libc::c_int;
    fn freeifaddrs(__ifa: *mut ifaddrs);

    fn init_hostkeys() -> *mut hostkeys;
    fn load_hostkeys(_: *mut hostkeys, _: *const libc::c_char, _: *const libc::c_char, _: u_int);
    fn load_hostkeys_file(
        _: *mut hostkeys,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut libc::FILE,
        note: u_int,
    );
    fn free_hostkeys(_: *mut hostkeys);
    fn check_key_in_hostkeys(
        _: *mut hostkeys,
        _: *mut crate::sshkey::sshkey,
        _: *mut *const hostkey_entry,
    ) -> HostStatus;
    fn lookup_key_in_hostkeys_by_type(
        _: *mut hostkeys,
        _: libc::c_int,
        _: libc::c_int,
        _: *mut *const hostkey_entry,
    ) -> libc::c_int;
    fn add_host_to_hostfile(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *const crate::sshkey::sshkey,
        _: libc::c_int,
    ) -> libc::c_int;
    fn hostkeys_foreach(
        path: *const libc::c_char,
        callback: Option<hostkeys_foreach_fn>,
        ctx: *mut libc::c_void,
        host: *const libc::c_char,
        ip: *const libc::c_char,
        options_0: u_int,
        note: u_int,
    ) -> libc::c_int;
    fn ssh_packet_set_connection(_: *mut ssh, _: libc::c_int, _: libc::c_int) -> *mut ssh;
    fn ssh_packet_set_nonblocking(_: *mut ssh);
    fn sshpkt_fatal(ssh: *mut ssh, r: libc::c_int, fmt: *const libc::c_char, _: ...) -> !;
    fn sshkey_to_base64(_: *const crate::sshkey::sshkey, _: *mut *mut libc::c_char) -> libc::c_int;
    fn sshkey_ssh_name(_: *const crate::sshkey::sshkey) -> *const libc::c_char;

    fn sshkey_equal(
        _: *const crate::sshkey::sshkey,
        _: *const crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_fingerprint(
        _: *const crate::sshkey::sshkey,
        _: libc::c_int,
        _: sshkey_fp_rep,
    ) -> *mut libc::c_char;
    fn sshkey_type(_: *const crate::sshkey::sshkey) -> *const libc::c_char;
    fn sshkey_from_private(
        _: *const crate::sshkey::sshkey,
        _: *mut *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_is_cert(_: *const crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_is_sk(_: *const crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_drop_cert(_: *mut crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_cert_check_host(
        _: *const crate::sshkey::sshkey,
        _: *const libc::c_char,
        _: libc::c_int,
        _: *const libc::c_char,
        _: *mut *const libc::c_char,
    ) -> libc::c_int;
    fn sshkey_format_cert_validity(
        _: *const crate::sshkey::sshkey_cert,
        _: *mut libc::c_char,
        _: size_t,
    ) -> size_t;
    fn ssh_kex2(
        ssh: *mut ssh,
        _: *mut libc::c_char,
        _: *mut sockaddr,
        _: u_short,
        _: *const ssh_conn_info,
    );
    fn ssh_userauth2(
        ssh: *mut ssh,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: *mut libc::c_char,
        _: *mut Sensitive,
    );

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
    fn set_sock_tos(_: libc::c_int, _: libc::c_int);
    fn timeout_connect(
        _: libc::c_int,
        _: *const sockaddr,
        _: socklen_t,
        _: *mut libc::c_int,
    ) -> libc::c_int;
    fn put_host_port(_: *const libc::c_char, _: u_short) -> *mut libc::c_char;
    fn percent_expand(_: *const libc::c_char, _: ...) -> *mut libc::c_char;
    fn percent_dollar_expand(_: *const libc::c_char, _: ...) -> *mut libc::c_char;
    fn xextendf(
        s: *mut *mut libc::c_char,
        sep: *const libc::c_char,
        fmt: *const libc::c_char,
        _: ...
    );
    fn lowercase(s: *mut libc::c_char);
    fn stdfd_devnull(_: libc::c_int, _: libc::c_int, _: libc::c_int) -> libc::c_int;
    fn ssh_gai_strerror(_: libc::c_int) -> *const libc::c_char;
    fn subprocess(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
        _: *mut *mut libc::c_char,
        _: *mut *mut libc::FILE,
        _: u_int,
        _: *mut libc::passwd,
        _: Option<privdrop_fn>,
        _: Option<privrestore_fn>,
    ) -> pid_t;
    fn argv_split(
        _: *const libc::c_char,
        _: *mut libc::c_int,
        _: *mut *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn argv_assemble(_: libc::c_int, argv: *mut *mut libc::c_char) -> *mut libc::c_char;
    fn exited_cleanly(
        _: pid_t,
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn read_passphrase(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn ask_permission(_: *const libc::c_char, _: ...) -> libc::c_int;

    fn verify_host_key_dns(
        _: *const libc::c_char,
        _: *mut sockaddr,
        _: *mut crate::sshkey::sshkey,
        _: *mut libc::c_int,
    ) -> libc::c_int;
    fn mm_receive_fd(_: libc::c_int) -> libc::c_int;
    fn sshkey_check_revoked(
        key: *mut crate::sshkey::sshkey,
        revoked_keys_file: *const libc::c_char,
    ) -> libc::c_int;
    fn ssh_get_authentication_socket(fdp: *mut libc::c_int) -> libc::c_int;
    fn ssh_add_identity_constrained(
        sock: libc::c_int,
        key: *mut crate::sshkey::sshkey,
        comment: *const libc::c_char,
        life: u_int,
        confirm_0: u_int,
        maxsign: u_int,
        provider: *const libc::c_char,
        dest_constraints: *mut *mut dest_constraint,
        ndest_constraints: size_t,
    ) -> libc::c_int;
    fn kex_exchange_identification(
        _: *mut ssh,
        _: libc::c_int,
        _: *const libc::c_char,
    ) -> libc::c_int;
    static mut debug_flag: libc::c_int;
    static mut options: Options;
}
pub type __u_char = libc::c_uchar;
pub type __u_short = libc::c_ushort;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __int64_t = libc::c_long;
pub type __uint64_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __mode_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __socklen_t = libc::c_uint;
pub type __sig_atomic_t = libc::c_int;
pub type u_char = __u_char;
pub type u_short = __u_short;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type mode_t = __mode_t;
pub type pid_t = __pid_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
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
    pub key: *mut crate::sshkey::sshkey,
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
    pub initial_hostkey: *mut crate::sshkey::sshkey,
    pub done: sig_atomic_t,
    pub flags: u_int,
    pub hash_alg: libc::c_int,
    pub ec_nid: libc::c_int,
    pub failed_choice: *mut libc::c_char,
    pub verify_host_key:
        Option<unsafe extern "C" fn(*mut crate::sshkey::sshkey, *mut ssh) -> libc::c_int>,
    pub load_host_public_key: Option<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut crate::sshkey::sshkey,
    >,
    pub load_host_private_key: Option<
        unsafe extern "C" fn(libc::c_int, libc::c_int, *mut ssh) -> *mut crate::sshkey::sshkey,
    >,
    pub host_key_index: Option<
        unsafe extern "C" fn(*mut crate::sshkey::sshkey, libc::c_int, *mut ssh) -> libc::c_int,
    >,
    pub sign: Option<
        unsafe extern "C" fn(
            *mut ssh,
            *mut crate::sshkey::sshkey,
            *mut crate::sshkey::sshkey,
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
    pub ec_client_key: *mut crate::sshkey::EC_KEY,
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
pub type C2RustUnnamed_3 = libc::c_uint;
pub const IFF_DYNAMIC: C2RustUnnamed_3 = 32768;
pub const IFF_AUTOMEDIA: C2RustUnnamed_3 = 16384;
pub const IFF_PORTSEL: C2RustUnnamed_3 = 8192;
pub const IFF_MULTICAST: C2RustUnnamed_3 = 4096;
pub const IFF_SLAVE: C2RustUnnamed_3 = 2048;
pub const IFF_MASTER: C2RustUnnamed_3 = 1024;
pub const IFF_ALLMULTI: C2RustUnnamed_3 = 512;
pub const IFF_PROMISC: C2RustUnnamed_3 = 256;
pub const IFF_NOARP: C2RustUnnamed_3 = 128;
pub const IFF_RUNNING: C2RustUnnamed_3 = 64;
pub const IFF_NOTRAILERS: C2RustUnnamed_3 = 32;
pub const IFF_POINTOPOINT: C2RustUnnamed_3 = 16;
pub const IFF_LOOPBACK: C2RustUnnamed_3 = 8;
pub const IFF_DEBUG: C2RustUnnamed_3 = 4;
pub const IFF_BROADCAST: C2RustUnnamed_3 = 2;
pub const IFF_UP: C2RustUnnamed_3 = 1;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ifaddrs {
    pub ifa_next: *mut ifaddrs,
    pub ifa_name: *mut libc::c_char,
    pub ifa_flags: libc::c_uint,
    pub ifa_addr: *mut sockaddr,
    pub ifa_netmask: *mut sockaddr,
    pub ifa_ifu: C2RustUnnamed_4,
    pub ifa_data: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_4 {
    pub ifu_broadaddr: *mut sockaddr,
    pub ifu_dstaddr: *mut sockaddr,
}
pub type HostStatus = libc::c_uint;
pub const HOST_FOUND: HostStatus = 4;
pub const HOST_REVOKED: HostStatus = 3;
pub const HOST_CHANGED: HostStatus = 2;
pub const HOST_NEW: HostStatus = 1;
pub const HOST_OK: HostStatus = 0;
pub type HostkeyMarker = libc::c_uint;
pub const MRK_CA: HostkeyMarker = 3;
pub const MRK_REVOKE: HostkeyMarker = 2;
pub const MRK_NONE: HostkeyMarker = 1;
pub const MRK_ERROR: HostkeyMarker = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostkey_entry {
    pub host: *mut libc::c_char,
    pub file: *mut libc::c_char,
    pub line: u_long,
    pub key: *mut crate::sshkey::sshkey,
    pub marker: HostkeyMarker,
    pub note: u_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct hostkeys {
    pub entries: *mut hostkey_entry,
    pub num_entries: u_int,
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
    pub key: *mut crate::sshkey::sshkey,
    pub comment: *const libc::c_char,
    pub note: u_int,
}
pub type hostkeys_foreach_fn =
    unsafe extern "C" fn(*mut hostkey_foreach_line, *mut libc::c_void) -> libc::c_int;
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
pub struct Sensitive {
    pub keys: *mut *mut crate::sshkey::sshkey,
    pub nkeys: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ssh_conn_info {
    pub conn_hash_hex: *mut libc::c_char,
    pub shorthost: *mut libc::c_char,
    pub uidstr: *mut libc::c_char,
    pub keyalias: *mut libc::c_char,
    pub thishost: *mut libc::c_char,
    pub host_arg: *mut libc::c_char,
    pub portstr: *mut libc::c_char,
    pub remhost: *mut libc::c_char,
    pub remuser: *mut libc::c_char,
    pub homedir: *mut libc::c_char,
    pub locuser: *mut libc::c_char,
}
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
    pub identity_keys: [*mut crate::sshkey::sshkey; 100],
    pub num_certificate_files: libc::c_int,
    pub certificate_files: [*mut libc::c_char; 100],
    pub certificate_file_userprovided: [libc::c_int; 100],
    pub certificates: [*mut crate::sshkey::sshkey; 100],
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
pub struct find_by_key_ctx {
    pub host: *const libc::c_char,
    pub ip: *const libc::c_char,
    pub key: *const crate::sshkey::sshkey,
    pub names: *mut *mut libc::c_char,
    pub nnames: u_int,
}
pub type privrestore_fn = unsafe extern "C" fn() -> ();
pub type privdrop_fn = unsafe extern "C" fn(*mut libc::passwd) -> ();
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dest_constraint {
    pub from: dest_constraint_hop,
    pub to: dest_constraint_hop,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dest_constraint_hop {
    pub user: *mut libc::c_char,
    pub hostname: *mut libc::c_char,
    pub is_ca: libc::c_int,
    pub nkeys: u_int,
    pub keys: *mut *mut crate::sshkey::sshkey,
    pub key_is_ca: *mut libc::c_int,
}
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
}
pub static mut previous_host_key: *mut crate::sshkey::sshkey =
    0 as *const crate::sshkey::sshkey as *mut crate::sshkey::sshkey;
static mut matching_host_key_dns: libc::c_int = 0 as libc::c_int;
static mut proxy_command_pid: pid_t = 0 as libc::c_int;
unsafe extern "C" fn expand_proxy_command(
    mut proxy_command: *const libc::c_char,
    mut _user: *const libc::c_char,
    mut host: *const libc::c_char,
    mut host_arg: *const libc::c_char,
    mut port: libc::c_int,
) -> *mut libc::c_char {
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut strport: [libc::c_char; 32] = [0; 32];
    let mut keyalias: *const libc::c_char = if !(options.host_key_alias).is_null() {
        options.host_key_alias as *const libc::c_char
    } else {
        host_arg
    };
    libc::snprintf(
        strport.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 32]>() as usize,
        b"%d\0" as *const u8 as *const libc::c_char,
        port,
    );
    crate::xmalloc::xasprintf(
        &mut tmp as *mut *mut libc::c_char,
        b"exec %s\0" as *const u8 as *const libc::c_char,
        proxy_command,
    );
    ret = percent_expand(
        tmp,
        b"h\0" as *const u8 as *const libc::c_char,
        host,
        b"k\0" as *const u8 as *const libc::c_char,
        keyalias,
        b"n\0" as *const u8 as *const libc::c_char,
        host_arg,
        b"p\0" as *const u8 as *const libc::c_char,
        strport.as_mut_ptr(),
        b"r\0" as *const u8 as *const libc::c_char,
        options.user,
        0 as *mut libc::c_void as *mut libc::c_char,
    );
    libc::free(tmp as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn ssh_proxy_fdpass_connect(
    mut ssh: *mut ssh,
    mut host: *const libc::c_char,
    mut host_arg: *const libc::c_char,
    mut port: u_short,
    mut proxy_command: *const libc::c_char,
) -> libc::c_int {
    let mut command_string: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut sp: [libc::c_int; 2] = [0; 2];
    let mut sock: libc::c_int = 0;
    let mut pid: pid_t = 0;
    let mut shell: *mut libc::c_char = 0 as *mut libc::c_char;
    shell = getenv(b"SHELL\0" as *const u8 as *const libc::c_char);
    if shell.is_null() {
        shell = b"/bin/sh\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if libc::socketpair(
        1 as libc::c_int,
        SOCK_STREAM as libc::c_int,
        0 as libc::c_int,
        sp.as_mut_ptr(),
    ) == -(1 as libc::c_int)
    {
        sshfatal(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"ssh_proxy_fdpass_connect\0",
            ))
            .as_ptr(),
            126 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Could not create libc::socketpair to communicate with proxy dialer: %.100s\0"
                as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    command_string = expand_proxy_command(
        proxy_command,
        options.user,
        host,
        host_arg,
        port as libc::c_int,
    );
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"ssh_proxy_fdpass_connect\0"))
            .as_ptr(),
        130 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Executing proxy dialer command: %.500s\0" as *const u8 as *const libc::c_char,
        command_string,
    );
    pid = libc::fork();
    if pid == 0 as libc::c_int {
        let mut argv: [*mut libc::c_char; 10] = [0 as *mut libc::c_char; 10];
        close(sp[1 as libc::c_int as usize]);
        if sp[0 as libc::c_int as usize] != 0 as libc::c_int {
            if libc::dup2(sp[0 as libc::c_int as usize], 0 as libc::c_int) == -(1 as libc::c_int) {
                libc::perror(b"libc::dup2 stdin\0" as *const u8 as *const libc::c_char);
            }
        }
        if sp[0 as libc::c_int as usize] != 1 as libc::c_int {
            if libc::dup2(sp[0 as libc::c_int as usize], 1 as libc::c_int) == -(1 as libc::c_int) {
                libc::perror(b"libc::dup2 stdout\0" as *const u8 as *const libc::c_char);
            }
        }
        if sp[0 as libc::c_int as usize] >= 2 as libc::c_int {
            close(sp[0 as libc::c_int as usize]);
        }
        if debug_flag == 0
            && !(options.control_path).is_null()
            && options.control_persist != 0
            && stdfd_devnull(0 as libc::c_int, 0 as libc::c_int, 1 as libc::c_int)
                == -(1 as libc::c_int)
        {
            crate::log::sshlog(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"ssh_proxy_fdpass_connect\0",
                ))
                .as_ptr(),
                155 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"stdfd_devnull failed\0" as *const u8 as *const libc::c_char,
            );
        }
        argv[0 as libc::c_int as usize] = shell;
        argv[1 as libc::c_int as usize] =
            b"-c\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        argv[2 as libc::c_int as usize] = command_string;
        argv[3 as libc::c_int as usize] = 0 as *mut libc::c_char;
        execv(
            argv[0 as libc::c_int as usize],
            argv.as_mut_ptr() as *const *mut libc::c_char,
        );
        libc::perror(argv[0 as libc::c_int as usize]);
        libc::exit(1 as libc::c_int);
    }
    if pid == -(1 as libc::c_int) {
        sshfatal(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"ssh_proxy_fdpass_connect\0",
            ))
            .as_ptr(),
            172 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::fork failed: %.100s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    close(sp[0 as libc::c_int as usize]);
    libc::free(command_string as *mut libc::c_void);
    sock = mm_receive_fd(sp[1 as libc::c_int as usize]);
    if sock == -(1 as libc::c_int) {
        sshfatal(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"ssh_proxy_fdpass_connect\0",
            ))
            .as_ptr(),
            177 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"proxy dialer did not pass back a connection\0" as *const u8 as *const libc::c_char,
        );
    }
    close(sp[1 as libc::c_int as usize]);
    while libc::waitpid(pid, 0 as *mut libc::c_int, 0 as libc::c_int) == -(1 as libc::c_int) {
        if *libc::__errno_location() != 4 as libc::c_int {
            sshfatal(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"ssh_proxy_fdpass_connect\0",
                ))
                .as_ptr(),
                182 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Couldn't wait for child: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
    }
    if (ssh_packet_set_connection(ssh, sock, sock)).is_null() {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn ssh_proxy_connect(
    mut ssh: *mut ssh,
    mut host: *const libc::c_char,
    mut host_arg: *const libc::c_char,
    mut port: u_short,
    mut proxy_command: *const libc::c_char,
) -> libc::c_int {
    let mut command_string: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pin: [libc::c_int; 2] = [0; 2];
    let mut pout: [libc::c_int; 2] = [0; 2];
    let mut pid: pid_t = 0;
    let mut shell: *mut libc::c_char = 0 as *mut libc::c_char;
    shell = getenv(b"SHELL\0" as *const u8 as *const libc::c_char);
    if shell.is_null() || *shell as libc::c_int == '\0' as i32 {
        shell = b"/bin/sh\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    if pipe(pin.as_mut_ptr()) == -(1 as libc::c_int)
        || pipe(pout.as_mut_ptr()) == -(1 as libc::c_int)
    {
        sshfatal(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_proxy_connect\0"))
                .as_ptr(),
            209 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"Could not create pipes to communicate with the proxy: %.100s\0" as *const u8
                as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    command_string = expand_proxy_command(
        proxy_command,
        options.user,
        host,
        host_arg,
        port as libc::c_int,
    );
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_proxy_connect\0"))
            .as_ptr(),
        213 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Executing proxy command: %.500s\0" as *const u8 as *const libc::c_char,
        command_string,
    );
    pid = libc::fork();
    if pid == 0 as libc::c_int {
        let mut argv: [*mut libc::c_char; 10] = [0 as *mut libc::c_char; 10];
        close(pin[1 as libc::c_int as usize]);
        if pin[0 as libc::c_int as usize] != 0 as libc::c_int {
            if libc::dup2(pin[0 as libc::c_int as usize], 0 as libc::c_int) == -(1 as libc::c_int) {
                libc::perror(b"libc::dup2 stdin\0" as *const u8 as *const libc::c_char);
            }
            close(pin[0 as libc::c_int as usize]);
        }
        close(pout[0 as libc::c_int as usize]);
        if libc::dup2(pout[1 as libc::c_int as usize], 1 as libc::c_int) == -(1 as libc::c_int) {
            libc::perror(b"libc::dup2 stdout\0" as *const u8 as *const libc::c_char);
        }
        close(pout[1 as libc::c_int as usize]);
        if debug_flag == 0
            && !(options.control_path).is_null()
            && options.control_persist != 0
            && stdfd_devnull(0 as libc::c_int, 0 as libc::c_int, 1 as libc::c_int)
                == -(1 as libc::c_int)
        {
            crate::log::sshlog(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_proxy_connect\0"))
                    .as_ptr(),
                238 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"stdfd_devnull failed\0" as *const u8 as *const libc::c_char,
            );
        }
        argv[0 as libc::c_int as usize] = shell;
        argv[1 as libc::c_int as usize] =
            b"-c\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
        argv[2 as libc::c_int as usize] = command_string;
        argv[3 as libc::c_int as usize] = 0 as *mut libc::c_char;
        crate::misc::ssh_signal(13 as libc::c_int, None);
        execv(
            argv[0 as libc::c_int as usize],
            argv.as_mut_ptr() as *const *mut libc::c_char,
        );
        libc::perror(argv[0 as libc::c_int as usize]);
        libc::exit(1 as libc::c_int);
    }
    if pid == -(1 as libc::c_int) {
        sshfatal(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_proxy_connect\0"))
                .as_ptr(),
            256 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::fork failed: %.100s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    } else {
        proxy_command_pid = pid;
    }
    close(pin[0 as libc::c_int as usize]);
    close(pout[1 as libc::c_int as usize]);
    libc::free(command_string as *mut libc::c_void);
    if (ssh_packet_set_connection(
        ssh,
        pout[0 as libc::c_int as usize],
        pin[1 as libc::c_int as usize],
    ))
    .is_null()
    {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_kill_proxy_command() {
    if proxy_command_pid > 1 as libc::c_int {
        kill(proxy_command_pid, 1 as libc::c_int);
    }
}
unsafe extern "C" fn check_ifaddrs(
    mut _ifname: *const libc::c_char,
    mut af: libc::c_int,
    mut ifaddrs: *const ifaddrs,
    mut resultp: *mut sockaddr_storage,
    mut rlenp: *mut socklen_t,
) -> libc::c_int {
    let mut sa6: *mut sockaddr_in6 = 0 as *mut sockaddr_in6;
    let mut sa: *mut sockaddr_in = 0 as *mut sockaddr_in;
    let mut v6addr: *mut in6_addr = 0 as *mut in6_addr;
    let mut ifa: *const ifaddrs = 0 as *const ifaddrs;
    let mut allow_local: libc::c_int = 0;
    allow_local = 0 as libc::c_int;
    while allow_local < 2 as libc::c_int {
        let mut current_block_18: u64;
        ifa = ifaddrs;
        while !ifa.is_null() {
            if !(((*ifa).ifa_addr).is_null()
                || ((*ifa).ifa_name).is_null()
                || (*ifa).ifa_flags & IFF_UP as libc::c_int as libc::c_uint
                    == 0 as libc::c_int as libc::c_uint
                || (*(*ifa).ifa_addr).sa_family as libc::c_int != af
                || libc::strcmp((*ifa).ifa_name, options.bind_interface) != 0 as libc::c_int)
            {
                match (*(*ifa).ifa_addr).sa_family as libc::c_int {
                    2 => {
                        current_block_18 = 17765817032437731097;
                        match current_block_18 {
                            17442480678622601751 => {
                                sa6 = (*ifa).ifa_addr as *mut sockaddr_in6;
                                v6addr = &mut (*sa6).sin6_addr;
                                if !(allow_local == 0
                                    && (({
                                        let mut __a: *const in6_addr = v6addr as *const in6_addr;
                                        ((*__a).__in6_u.__u6_addr32[0 as libc::c_int as usize]
                                            & __bswap_32(0xffc00000 as libc::c_uint)
                                            == __bswap_32(0xfe800000 as libc::c_uint))
                                            as libc::c_int
                                    }) != 0
                                        || ({
                                            let mut __a: *const in6_addr =
                                                v6addr as *const in6_addr;
                                            ((*__a).__in6_u.__u6_addr32[0 as libc::c_int as usize]
                                                == 0 as libc::c_int as libc::c_uint
                                                && (*__a).__in6_u.__u6_addr32
                                                    [1 as libc::c_int as usize]
                                                    == 0 as libc::c_int as libc::c_uint
                                                && (*__a).__in6_u.__u6_addr32
                                                    [2 as libc::c_int as usize]
                                                    == 0 as libc::c_int as libc::c_uint
                                                && (*__a).__in6_u.__u6_addr32
                                                    [3 as libc::c_int as usize]
                                                    == __bswap_32(1 as libc::c_int as __uint32_t))
                                                as libc::c_int
                                        }) != 0))
                                {
                                    if (*rlenp as libc::c_ulong)
                                        < ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong
                                    {
                                        crate::log::sshlog(
                                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 14],
                                                &[libc::c_char; 14],
                                            >(
                                                b"check_ifaddrs\0"
                                            ))
                                            .as_ptr(),
                                            333 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"v6 addr doesn't fit\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        return -(1 as libc::c_int);
                                    }
                                    *rlenp = ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong
                                        as socklen_t;
                                    memcpy(
                                        resultp as *mut libc::c_void,
                                        sa6 as *const libc::c_void,
                                        *rlenp as libc::c_ulong,
                                    );
                                    return 0 as libc::c_int;
                                }
                            }
                            _ => {
                                sa = (*ifa).ifa_addr as *mut sockaddr_in;
                                if !(allow_local == 0
                                    && (*sa).sin_addr.s_addr
                                        == __bswap_32(0x7f000001 as libc::c_int as in_addr_t))
                                {
                                    if (*rlenp as libc::c_ulong)
                                        < ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong
                                    {
                                        crate::log::sshlog(
                                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 14],
                                                &[libc::c_char; 14],
                                            >(
                                                b"check_ifaddrs\0"
                                            ))
                                            .as_ptr(),
                                            319 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"v4 addr doesn't fit\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        return -(1 as libc::c_int);
                                    }
                                    *rlenp = ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong
                                        as socklen_t;
                                    memcpy(
                                        resultp as *mut libc::c_void,
                                        sa as *const libc::c_void,
                                        *rlenp as libc::c_ulong,
                                    );
                                    return 0 as libc::c_int;
                                }
                            }
                        }
                    }
                    10 => {
                        current_block_18 = 17442480678622601751;
                        match current_block_18 {
                            17442480678622601751 => {
                                sa6 = (*ifa).ifa_addr as *mut sockaddr_in6;
                                v6addr = &mut (*sa6).sin6_addr;
                                if !(allow_local == 0
                                    && (({
                                        let mut __a: *const in6_addr = v6addr as *const in6_addr;
                                        ((*__a).__in6_u.__u6_addr32[0 as libc::c_int as usize]
                                            & __bswap_32(0xffc00000 as libc::c_uint)
                                            == __bswap_32(0xfe800000 as libc::c_uint))
                                            as libc::c_int
                                    }) != 0
                                        || ({
                                            let mut __a: *const in6_addr =
                                                v6addr as *const in6_addr;
                                            ((*__a).__in6_u.__u6_addr32[0 as libc::c_int as usize]
                                                == 0 as libc::c_int as libc::c_uint
                                                && (*__a).__in6_u.__u6_addr32
                                                    [1 as libc::c_int as usize]
                                                    == 0 as libc::c_int as libc::c_uint
                                                && (*__a).__in6_u.__u6_addr32
                                                    [2 as libc::c_int as usize]
                                                    == 0 as libc::c_int as libc::c_uint
                                                && (*__a).__in6_u.__u6_addr32
                                                    [3 as libc::c_int as usize]
                                                    == __bswap_32(1 as libc::c_int as __uint32_t))
                                                as libc::c_int
                                        }) != 0))
                                {
                                    if (*rlenp as libc::c_ulong)
                                        < ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong
                                    {
                                        crate::log::sshlog(
                                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 14],
                                                &[libc::c_char; 14],
                                            >(
                                                b"check_ifaddrs\0"
                                            ))
                                            .as_ptr(),
                                            333 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"v6 addr doesn't fit\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        return -(1 as libc::c_int);
                                    }
                                    *rlenp = ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong
                                        as socklen_t;
                                    memcpy(
                                        resultp as *mut libc::c_void,
                                        sa6 as *const libc::c_void,
                                        *rlenp as libc::c_ulong,
                                    );
                                    return 0 as libc::c_int;
                                }
                            }
                            _ => {
                                sa = (*ifa).ifa_addr as *mut sockaddr_in;
                                if !(allow_local == 0
                                    && (*sa).sin_addr.s_addr
                                        == __bswap_32(0x7f000001 as libc::c_int as in_addr_t))
                                {
                                    if (*rlenp as libc::c_ulong)
                                        < ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong
                                    {
                                        crate::log::sshlog(
                                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 14],
                                                &[libc::c_char; 14],
                                            >(
                                                b"check_ifaddrs\0"
                                            ))
                                            .as_ptr(),
                                            319 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"v4 addr doesn't fit\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        return -(1 as libc::c_int);
                                    }
                                    *rlenp = ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong
                                        as socklen_t;
                                    memcpy(
                                        resultp as *mut libc::c_void,
                                        sa as *const libc::c_void,
                                        *rlenp as libc::c_ulong,
                                    );
                                    return 0 as libc::c_int;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            ifa = (*ifa).ifa_next;
        }
        allow_local += 1;
        allow_local;
    }
    return -(1 as libc::c_int);
}
unsafe extern "C" fn ssh_create_socket(mut ai: *mut addrinfo) -> libc::c_int {
    let mut current_block: u64;
    let mut sock: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut bindaddr: sockaddr_storage = sockaddr_storage {
        ss_family: 0,
        __ss_padding: [0; 118],
        __ss_align: 0,
    };
    let mut bindaddrlen: socklen_t = 0 as libc::c_int as socklen_t;
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
    let mut res: *mut addrinfo = 0 as *mut addrinfo;
    let mut ifaddrs: *mut ifaddrs = 0 as *mut ifaddrs;
    let mut ntop: [libc::c_char; 1025] = [0; 1025];
    sock = socket((*ai).ai_family, (*ai).ai_socktype, (*ai).ai_protocol);
    if sock == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_create_socket\0"))
                .as_ptr(),
            363 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"socket: %s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
        return -(1 as libc::c_int);
    }
    fcntl(sock, 2 as libc::c_int, 1 as libc::c_int);
    if options.ip_qos_interactive != 2147483647 as libc::c_int {
        set_sock_tos(sock, options.ip_qos_interactive);
    }
    if (options.bind_address).is_null() && (options.bind_interface).is_null() {
        return sock;
    }
    if !(options.bind_address).is_null() {
        memset(
            &mut hints as *mut addrinfo as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<addrinfo>() as libc::c_ulong,
        );
        hints.ai_family = (*ai).ai_family;
        hints.ai_socktype = (*ai).ai_socktype;
        hints.ai_protocol = (*ai).ai_protocol;
        hints.ai_flags = 0x1 as libc::c_int;
        r = getaddrinfo(
            options.bind_address,
            0 as *const libc::c_char,
            &mut hints,
            &mut res,
        );
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_create_socket\0"))
                    .as_ptr(),
                385 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"getaddrinfo: %s: %s\0" as *const u8 as *const libc::c_char,
                options.bind_address,
                ssh_gai_strerror(r),
            );
            current_block = 11409641321532490549;
        } else if res.is_null() {
            crate::log::sshlog(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_create_socket\0"))
                    .as_ptr(),
                389 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"getaddrinfo: no addrs\0" as *const u8 as *const libc::c_char,
            );
            current_block = 11409641321532490549;
        } else {
            memcpy(
                &mut bindaddr as *mut sockaddr_storage as *mut libc::c_void,
                (*res).ai_addr as *const libc::c_void,
                (*res).ai_addrlen as libc::c_ulong,
            );
            bindaddrlen = (*res).ai_addrlen;
            current_block = 2719512138335094285;
        }
    } else if !(options.bind_interface).is_null() {
        r = getifaddrs(&mut ifaddrs);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_create_socket\0"))
                    .as_ptr(),
                398 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"getifaddrs: %s: %s\0" as *const u8 as *const libc::c_char,
                options.bind_interface,
                libc::strerror(*libc::__errno_location()),
            );
            current_block = 11409641321532490549;
        } else {
            bindaddrlen = ::core::mem::size_of::<sockaddr_storage>() as libc::c_ulong as socklen_t;
            if check_ifaddrs(
                options.bind_interface,
                (*ai).ai_family,
                ifaddrs,
                &mut bindaddr,
                &mut bindaddrlen,
            ) != 0 as libc::c_int
            {
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"ssh_create_socket\0",
                    ))
                    .as_ptr(),
                    405 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"getifaddrs: %s: no suitable addresses\0" as *const u8 as *const libc::c_char,
                    options.bind_interface,
                );
                current_block = 11409641321532490549;
            } else {
                current_block = 2719512138335094285;
            }
        }
    } else {
        current_block = 2719512138335094285;
    }
    match current_block {
        2719512138335094285 => {
            r = getnameinfo(
                &mut bindaddr as *mut sockaddr_storage as *mut sockaddr,
                bindaddrlen,
                ntop.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as socklen_t,
                0 as *mut libc::c_char,
                0 as libc::c_int as socklen_t,
                1 as libc::c_int,
            );
            if r != 0 as libc::c_int {
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"ssh_create_socket\0",
                    ))
                    .as_ptr(),
                    414 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"getnameinfo failed: %s\0" as *const u8 as *const libc::c_char,
                    ssh_gai_strerror(r),
                );
                current_block = 11409641321532490549;
            } else if bind(
                sock,
                __CONST_SOCKADDR_ARG {
                    __sockaddr__: &mut bindaddr as *mut sockaddr_storage as *mut sockaddr,
                },
                bindaddrlen,
            ) != 0 as libc::c_int
            {
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"ssh_create_socket\0",
                    ))
                    .as_ptr(),
                    418 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"bind %s: %s\0" as *const u8 as *const libc::c_char,
                    ntop.as_mut_ptr(),
                    libc::strerror(*libc::__errno_location()),
                );
                current_block = 11409641321532490549;
            } else {
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"ssh_create_socket\0",
                    ))
                    .as_ptr(),
                    421 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"bound to %s\0" as *const u8 as *const libc::c_char,
                    ntop.as_mut_ptr(),
                );
                current_block = 5620008004080392;
            }
        }
        _ => {}
    }
    match current_block {
        11409641321532490549 => {
            close(sock);
            sock = -(1 as libc::c_int);
        }
        _ => {}
    }
    if !res.is_null() {
        freeaddrinfo(res);
    }
    if !ifaddrs.is_null() {
        freeifaddrs(ifaddrs);
    }
    return sock;
}
unsafe extern "C" fn ssh_connect_direct(
    mut ssh: *mut ssh,
    mut host: *const libc::c_char,
    mut aitop: *mut addrinfo,
    mut hostaddr: *mut sockaddr_storage,
    mut _port: u_short,
    mut connection_attempts: libc::c_int,
    mut timeout_ms: *mut libc::c_int,
    mut want_keepalive: libc::c_int,
) -> libc::c_int {
    let mut on: libc::c_int = 1 as libc::c_int;
    let mut saved_timeout_ms: libc::c_int = *timeout_ms;
    let mut oerrno: libc::c_int = 0;
    let mut sock: libc::c_int = -(1 as libc::c_int);
    let mut attempt: libc::c_int = 0;
    let mut ntop: [libc::c_char; 1025] = [0; 1025];
    let mut strport: [libc::c_char; 32] = [0; 32];
    let mut ai: *mut addrinfo = 0 as *mut addrinfo;
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"ssh_connect_direct\0"))
            .as_ptr(),
        456 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"entering\0" as *const u8 as *const libc::c_char,
    );
    memset(
        ntop.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong,
    );
    memset(
        strport.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
    );
    attempt = 0 as libc::c_int;
    while attempt < connection_attempts {
        if attempt > 0 as libc::c_int {
            sleep(1 as libc::c_int as libc::c_uint);
            crate::log::sshlog(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"ssh_connect_direct\0",
                ))
                .as_ptr(),
                464 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Trying again...\0" as *const u8 as *const libc::c_char,
            );
        }
        ai = aitop;
        while !ai.is_null() {
            if (*ai).ai_family != 2 as libc::c_int && (*ai).ai_family != 10 as libc::c_int {
                *libc::__errno_location() = 97 as libc::c_int;
            } else if getnameinfo(
                (*ai).ai_addr,
                (*ai).ai_addrlen,
                ntop.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as socklen_t,
                strport.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong as socklen_t,
                1 as libc::c_int | 2 as libc::c_int,
            ) != 0 as libc::c_int
            {
                oerrno = *libc::__errno_location();
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_connect_direct\0",
                    ))
                    .as_ptr(),
                    480 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"getnameinfo failed\0" as *const u8 as *const libc::c_char,
                );
                *libc::__errno_location() = oerrno;
            } else {
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"ssh_connect_direct\0",
                    ))
                    .as_ptr(),
                    485 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"Connecting to %.200s [%.100s] port %s.\0" as *const u8 as *const libc::c_char,
                    host,
                    ntop.as_mut_ptr(),
                    strport.as_mut_ptr(),
                );
                sock = ssh_create_socket(ai);
                if sock < 0 as libc::c_int {
                    *libc::__errno_location() = 0 as libc::c_int;
                } else {
                    *timeout_ms = saved_timeout_ms;
                    if timeout_connect(sock, (*ai).ai_addr, (*ai).ai_addrlen, timeout_ms)
                        >= 0 as libc::c_int
                    {
                        memcpy(
                            hostaddr as *mut libc::c_void,
                            (*ai).ai_addr as *const libc::c_void,
                            (*ai).ai_addrlen as libc::c_ulong,
                        );
                        break;
                    } else {
                        oerrno = *libc::__errno_location();
                        crate::log::sshlog(
                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                b"ssh_connect_direct\0",
                            ))
                            .as_ptr(),
                            504 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"connect to address %s port %s: %s\0" as *const u8
                                as *const libc::c_char,
                            ntop.as_mut_ptr(),
                            strport.as_mut_ptr(),
                            libc::strerror(*libc::__errno_location()),
                        );
                        close(sock);
                        sock = -(1 as libc::c_int);
                        *libc::__errno_location() = oerrno;
                    }
                }
            }
            ai = (*ai).ai_next;
        }
        if sock != -(1 as libc::c_int) {
            break;
        }
        attempt += 1;
        attempt;
    }
    if sock == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"ssh_connect_direct\0"))
                .as_ptr(),
            517 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"ssh: connect to host %s port %s: %s\0" as *const u8 as *const libc::c_char,
            host,
            strport.as_mut_ptr(),
            if *libc::__errno_location() == 0 as libc::c_int {
                b"failure\0" as *const u8 as *const libc::c_char
            } else {
                libc::strerror(*libc::__errno_location()) as *const libc::c_char
            },
        );
        return -(1 as libc::c_int);
    }
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"ssh_connect_direct\0"))
            .as_ptr(),
        521 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Connection established.\0" as *const u8 as *const libc::c_char,
    );
    if want_keepalive != 0
        && setsockopt(
            sock,
            1 as libc::c_int,
            9 as libc::c_int,
            &mut on as *mut libc::c_int as *mut libc::c_void,
            ::core::mem::size_of::<libc::c_int>() as libc::c_ulong as socklen_t,
        ) == -(1 as libc::c_int)
    {
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"ssh_connect_direct\0"))
                .as_ptr(),
            527 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"setsockopt SO_KEEPALIVE: %.100s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    if (ssh_packet_set_connection(ssh, sock, sock)).is_null() {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_connect(
    mut ssh: *mut ssh,
    mut host: *const libc::c_char,
    mut host_arg: *const libc::c_char,
    mut addrs: *mut addrinfo,
    mut hostaddr: *mut sockaddr_storage,
    mut port: u_short,
    mut connection_attempts: libc::c_int,
    mut timeout_ms: *mut libc::c_int,
    mut want_keepalive: libc::c_int,
) -> libc::c_int {
    let mut in_0: libc::c_int = 0;
    let mut out: libc::c_int = 0;
    if (options.proxy_command).is_null() {
        return ssh_connect_direct(
            ssh,
            host,
            addrs,
            hostaddr,
            port,
            connection_attempts,
            timeout_ms,
            want_keepalive,
        );
    } else if libc::strcmp(
        options.proxy_command,
        b"-\0" as *const u8 as *const libc::c_char,
    ) == 0 as libc::c_int
    {
        in_0 = dup(0 as libc::c_int);
        if in_0 == -(1 as libc::c_int) || {
            out = dup(1 as libc::c_int);
            out == -(1 as libc::c_int)
        } {
            if in_0 >= 0 as libc::c_int {
                close(in_0);
            }
            crate::log::sshlog(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"ssh_connect\0"))
                    .as_ptr(),
                551 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"dup() in/out failed\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        if (ssh_packet_set_connection(ssh, in_0, out)).is_null() {
            return -(1 as libc::c_int);
        }
        return 0 as libc::c_int;
    } else if options.proxy_use_fdpass != 0 {
        return ssh_proxy_fdpass_connect(ssh, host, host_arg, port, options.proxy_command);
    }
    return ssh_proxy_connect(ssh, host, host_arg, port, options.proxy_command);
}
unsafe extern "C" fn confirm(
    mut prompt: *const libc::c_char,
    mut fingerprint: *const libc::c_char,
) -> libc::c_int {
    let mut msg: *const libc::c_char = 0 as *const libc::c_char;
    let mut again: *const libc::c_char =
        b"Please type 'yes' or 'no': \0" as *const u8 as *const libc::c_char;
    let mut again_fp: *const libc::c_char =
        b"Please type 'yes', 'no' or the fingerprint: \0" as *const u8 as *const libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if options.batch_mode != 0 {
        return 0 as libc::c_int;
    }
    msg = prompt;
    loop {
        p = read_passphrase(msg, 0x1 as libc::c_int);
        cp = p;
        if p.is_null() {
            return 0 as libc::c_int;
        }
        p = p.offset(strspn(p, b" \t\0" as *const u8 as *const libc::c_char) as isize);
        *p.offset(strcspn(p, b" \t\n\0" as *const u8 as *const libc::c_char) as isize) =
            '\0' as i32 as libc::c_char;
        if *p.offset(0 as libc::c_int as isize) as libc::c_int == '\0' as i32
            || strcasecmp(p, b"no\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
        {
            ret = 0 as libc::c_int;
        } else if strcasecmp(p, b"yes\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int
            || !fingerprint.is_null() && libc::strcmp(p, fingerprint) == 0 as libc::c_int
        {
            ret = 1 as libc::c_int;
        }
        libc::free(cp as *mut libc::c_void);
        if ret != -(1 as libc::c_int) {
            return ret;
        }
        msg = if !fingerprint.is_null() {
            again_fp
        } else {
            again
        };
    }
}
unsafe extern "C" fn sockaddr_is_local(mut hostaddr: *mut sockaddr) -> libc::c_int {
    match (*hostaddr).sa_family as libc::c_int {
        2 => {
            return (__bswap_32((*(hostaddr as *mut sockaddr_in)).sin_addr.s_addr)
                >> 24 as libc::c_int
                == 127 as libc::c_int as libc::c_uint) as libc::c_int;
        }
        10 => {
            return {
                let mut __a: *const in6_addr = &mut (*(hostaddr as *mut sockaddr_in6)).sin6_addr
                    as *mut in6_addr
                    as *const in6_addr;
                ((*__a).__in6_u.__u6_addr32[0 as libc::c_int as usize]
                    == 0 as libc::c_int as libc::c_uint
                    && (*__a).__in6_u.__u6_addr32[1 as libc::c_int as usize]
                        == 0 as libc::c_int as libc::c_uint
                    && (*__a).__in6_u.__u6_addr32[2 as libc::c_int as usize]
                        == 0 as libc::c_int as libc::c_uint
                    && (*__a).__in6_u.__u6_addr32[3 as libc::c_int as usize]
                        == __bswap_32(1 as libc::c_int as __uint32_t))
                    as libc::c_int
            };
        }
        _ => return 0 as libc::c_int,
    };
}
pub unsafe extern "C" fn get_hostfile_hostname_ipaddr(
    mut hostname: *mut libc::c_char,
    mut hostaddr: *mut sockaddr,
    mut port: u_short,
    mut hostfile_hostname: *mut *mut libc::c_char,
    mut hostfile_ipaddr: *mut *mut libc::c_char,
) {
    let mut ntop: [libc::c_char; 1025] = [0; 1025];
    let mut addrlen: socklen_t = 0;
    match if hostaddr.is_null() {
        -(1 as libc::c_int)
    } else {
        (*hostaddr).sa_family as libc::c_int
    } {
        -1 => {
            addrlen = 0 as libc::c_int as socklen_t;
        }
        2 => {
            addrlen = ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong as socklen_t;
        }
        10 => {
            addrlen = ::core::mem::size_of::<sockaddr_in6>() as libc::c_ulong as socklen_t;
        }
        _ => {
            addrlen = ::core::mem::size_of::<sockaddr>() as libc::c_ulong as socklen_t;
        }
    }
    if !hostfile_ipaddr.is_null() {
        if (options.proxy_command).is_null() {
            if getnameinfo(
                hostaddr,
                addrlen,
                ntop.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as socklen_t,
                0 as *mut libc::c_char,
                0 as libc::c_int as socklen_t,
                1 as libc::c_int,
            ) != 0 as libc::c_int
            {
                sshfatal(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                        b"get_hostfile_hostname_ipaddr\0",
                    ))
                    .as_ptr(),
                    642 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"getnameinfo failed\0" as *const u8 as *const libc::c_char,
                );
            }
            *hostfile_ipaddr = put_host_port(ntop.as_mut_ptr(), port);
        } else {
            *hostfile_ipaddr = crate::xmalloc::xstrdup(
                b"<no hostip for proxy command>\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    if !hostfile_hostname.is_null() {
        if !(options.host_key_alias).is_null() {
            *hostfile_hostname = crate::xmalloc::xstrdup(options.host_key_alias);
            crate::log::sshlog(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                    b"get_hostfile_hostname_ipaddr\0",
                ))
                .as_ptr(),
                659 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"using hostkeyalias: %s\0" as *const u8 as *const libc::c_char,
                *hostfile_hostname,
            );
        } else {
            *hostfile_hostname = put_host_port(hostname, port);
        }
    }
}
unsafe extern "C" fn path_in_hostfiles(
    mut path: *const libc::c_char,
    mut hostfiles: *mut *mut libc::c_char,
    mut num_hostfiles: u_int,
) -> libc::c_int {
    let mut i: u_int = 0;
    i = 0 as libc::c_int as u_int;
    while i < num_hostfiles {
        if libc::strcmp(path, *hostfiles.offset(i as isize)) == 0 as libc::c_int {
            return 1 as libc::c_int;
        }
        i = i.wrapping_add(1);
        i;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn try_tilde_unexpand(mut path: *const libc::c_char) -> *mut libc::c_char {
    let mut home: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut l: size_t = 0;
    if *path as libc::c_int != '/' as i32 {
        return crate::xmalloc::xstrdup(path);
    }
    home = getenv(b"HOME\0" as *const u8 as *const libc::c_char);
    if home.is_null() || {
        l = strlen(home);
        l == 0 as libc::c_int as libc::c_ulong
    } {
        return crate::xmalloc::xstrdup(path);
    }
    if strncmp(path, home, l) != 0 as libc::c_int {
        return crate::xmalloc::xstrdup(path);
    }
    if *home.offset(l.wrapping_sub(1 as libc::c_int as libc::c_ulong) as isize) as libc::c_int
        != '/' as i32
        && *path.offset(l as isize) as libc::c_int != '/' as i32
    {
        return crate::xmalloc::xstrdup(path);
    }
    if *path.offset(l as isize) as libc::c_int == '/' as i32 {
        l = l.wrapping_add(1);
        l;
    }
    crate::xmalloc::xasprintf(
        &mut ret as *mut *mut libc::c_char,
        b"~/%s\0" as *const u8 as *const libc::c_char,
        path.offset(l as isize),
    );
    return ret;
}
unsafe extern "C" fn hostkeys_find_by_key_cb(
    mut l: *mut hostkey_foreach_line,
    mut _ctx: *mut libc::c_void,
) -> libc::c_int {
    let mut ctx: *mut find_by_key_ctx = _ctx as *mut find_by_key_ctx;
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    if (*l).match_0 & 1 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint {
        return 0 as libc::c_int;
    }
    if (*l).marker != MRK_NONE as libc::c_int {
        return 0 as libc::c_int;
    }
    if ((*l).key).is_null() || sshkey_equal((*ctx).key, (*l).key) == 0 {
        return 0 as libc::c_int;
    }
    path = try_tilde_unexpand((*l).path);
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"hostkeys_find_by_key_cb\0"))
            .as_ptr(),
        728 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"found matching key in %s:%lu\0" as *const u8 as *const libc::c_char,
        path,
        (*l).linenum,
    );
    (*ctx).names = crate::xmalloc::xrecallocarray(
        (*ctx).names as *mut libc::c_void,
        (*ctx).nnames as size_t,
        ((*ctx).nnames).wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
        ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
    ) as *mut *mut libc::c_char;
    crate::xmalloc::xasprintf(
        &mut *((*ctx).names).offset((*ctx).nnames as isize) as *mut *mut libc::c_char,
        b"%s:%lu: %s\0" as *const u8 as *const libc::c_char,
        path,
        (*l).linenum,
        if strncmp(
            (*l).hosts,
            b"|1|\0" as *const u8 as *const libc::c_char,
            strlen(b"|1|\0" as *const u8 as *const libc::c_char),
        ) == 0 as libc::c_int
        {
            b"[hashed name]\0" as *const u8 as *const libc::c_char
        } else {
            (*l).hosts
        },
    );
    (*ctx).nnames = ((*ctx).nnames).wrapping_add(1);
    (*ctx).nnames;
    libc::free(path as *mut libc::c_void);
    return 0 as libc::c_int;
}
unsafe extern "C" fn hostkeys_find_by_key_hostfile(
    mut file: *const libc::c_char,
    mut which: *const libc::c_char,
    mut ctx: *mut find_by_key_ctx,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
            b"hostkeys_find_by_key_hostfile\0",
        ))
        .as_ptr(),
        745 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"trying %s hostfile \"%s\"\0" as *const u8 as *const libc::c_char,
        which,
        file,
    );
    r = hostkeys_foreach(
        file,
        Some(
            hostkeys_find_by_key_cb
                as unsafe extern "C" fn(
                    *mut hostkey_foreach_line,
                    *mut libc::c_void,
                ) -> libc::c_int,
        ),
        ctx as *mut libc::c_void,
        (*ctx).host,
        (*ctx).ip,
        ((1 as libc::c_int) << 1 as libc::c_int) as u_int,
        0 as libc::c_int as u_int,
    );
    if r != 0 as libc::c_int {
        if r == -(24 as libc::c_int) && *libc::__errno_location() == 2 as libc::c_int {
            crate::log::sshlog(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                    b"hostkeys_find_by_key_hostfile\0",
                ))
                .as_ptr(),
                749 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"hostkeys file %s does not exist\0" as *const u8 as *const libc::c_char,
                file,
            );
            return 0 as libc::c_int;
        }
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 30], &[libc::c_char; 30]>(
                b"hostkeys_find_by_key_hostfile\0",
            ))
            .as_ptr(),
            752 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"hostkeys_foreach failed for %s\0" as *const u8 as *const libc::c_char,
            file,
        );
        return r;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn hostkeys_find_by_key(
    mut host: *const libc::c_char,
    mut ip: *const libc::c_char,
    mut key: *const crate::sshkey::sshkey,
    mut user_hostfiles: *mut *mut libc::c_char,
    mut num_user_hostfiles: u_int,
    mut system_hostfiles: *mut *mut libc::c_char,
    mut num_system_hostfiles: u_int,
    mut names: *mut *mut *mut libc::c_char,
    mut nnames: *mut u_int,
) {
    let mut current_block: u64;
    let mut ctx: find_by_key_ctx = {
        let mut init = find_by_key_ctx {
            host: 0 as *const libc::c_char,
            ip: 0 as *const libc::c_char,
            key: 0 as *const crate::sshkey::sshkey,
            names: 0 as *mut *mut libc::c_char,
            nnames: 0 as libc::c_int as u_int,
        };
        init
    };
    let mut i: u_int = 0;
    *names = 0 as *mut *mut libc::c_char;
    *nnames = 0 as libc::c_int as u_int;
    if key.is_null() || sshkey_is_cert(key) != 0 {
        return;
    }
    ctx.host = host;
    ctx.ip = ip;
    ctx.key = key;
    i = 0 as libc::c_int as u_int;
    loop {
        if !(i < num_user_hostfiles) {
            current_block = 13513818773234778473;
            break;
        }
        if hostkeys_find_by_key_hostfile(
            *user_hostfiles.offset(i as isize),
            b"user\0" as *const u8 as *const libc::c_char,
            &mut ctx,
        ) != 0 as libc::c_int
        {
            current_block = 3373203238429256392;
            break;
        }
        i = i.wrapping_add(1);
        i;
    }
    match current_block {
        13513818773234778473 => {
            i = 0 as libc::c_int as u_int;
            loop {
                if !(i < num_system_hostfiles) {
                    current_block = 5399440093318478209;
                    break;
                }
                if hostkeys_find_by_key_hostfile(
                    *system_hostfiles.offset(i as isize),
                    b"system\0" as *const u8 as *const libc::c_char,
                    &mut ctx,
                ) != 0 as libc::c_int
                {
                    current_block = 3373203238429256392;
                    break;
                }
                i = i.wrapping_add(1);
                i;
            }
            match current_block {
                3373203238429256392 => {}
                _ => {
                    *names = ctx.names;
                    *nnames = ctx.nnames;
                    ctx.names = 0 as *mut *mut libc::c_char;
                    ctx.nnames = 0 as libc::c_int as u_int;
                    return;
                }
            }
        }
        _ => {}
    }
    i = 0 as libc::c_int as u_int;
    while i < ctx.nnames {
        libc::free(*(ctx.names).offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free(ctx.names as *mut libc::c_void);
}
unsafe extern "C" fn other_hostkeys_message(
    mut host: *const libc::c_char,
    mut ip: *const libc::c_char,
    mut key: *const crate::sshkey::sshkey,
    mut user_hostfiles: *mut *mut libc::c_char,
    mut num_user_hostfiles: u_int,
    mut system_hostfiles: *mut *mut libc::c_char,
    mut num_system_hostfiles: u_int,
) -> *mut libc::c_char {
    let mut ret: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut othernames: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut i: u_int = 0;
    let mut n: u_int = 0;
    let mut num_othernames: u_int = 0 as libc::c_int as u_int;
    hostkeys_find_by_key(
        host,
        ip,
        key,
        user_hostfiles,
        num_user_hostfiles,
        system_hostfiles,
        num_system_hostfiles,
        &mut othernames,
        &mut num_othernames,
    );
    if num_othernames == 0 as libc::c_int as libc::c_uint {
        return crate::xmalloc::xstrdup(
            b"This key is not known by any other names.\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::xmalloc::xasprintf(
        &mut ret as *mut *mut libc::c_char,
        b"This host key is known by the following other names/addresses:\0" as *const u8
            as *const libc::c_char,
    );
    n = num_othernames;
    if n > 8 as libc::c_int as libc::c_uint {
        n = 8 as libc::c_int as u_int;
    }
    i = 0 as libc::c_int as u_int;
    while i < n {
        xextendf(
            &mut ret as *mut *mut libc::c_char,
            b"\n\0" as *const u8 as *const libc::c_char,
            b"    %s\0" as *const u8 as *const libc::c_char,
            *othernames.offset(i as isize),
        );
        i = i.wrapping_add(1);
        i;
    }
    if n < num_othernames {
        xextendf(
            &mut ret as *mut *mut libc::c_char,
            b"\n\0" as *const u8 as *const libc::c_char,
            b"    (%d additional names omitted)\0" as *const u8 as *const libc::c_char,
            num_othernames.wrapping_sub(n),
        );
    }
    i = 0 as libc::c_int as u_int;
    while i < num_othernames {
        libc::free(*othernames.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free(othernames as *mut libc::c_void);
    return ret;
}
pub unsafe extern "C" fn load_hostkeys_command(
    mut hostkeys: *mut hostkeys,
    mut command_template: *const libc::c_char,
    mut invocation: *const libc::c_char,
    mut cinfo: *const ssh_conn_info,
    mut host_key: *const crate::sshkey::sshkey,
    mut hostfile_hostname: *const libc::c_char,
) {
    let mut r: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut ac: libc::c_int = 0 as libc::c_int;
    let mut key_fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut keytext: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tmp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut command: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut tag: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut av: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut pid: pid_t = 0;
    let mut osigchld: Option<unsafe extern "C" fn(libc::c_int) -> ()> = None;
    crate::xmalloc::xasprintf(
        &mut tag as *mut *mut libc::c_char,
        b"KnownHostsCommand-%s\0" as *const u8 as *const libc::c_char,
        invocation,
    );
    if !host_key.is_null() {
        key_fp = sshkey_fingerprint(host_key, options.fingerprint_hash, SSH_FP_DEFAULT);
        if key_fp.is_null() {
            sshfatal(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"load_hostkeys_command\0",
                ))
                .as_ptr(),
                856 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
            );
        }
        r = sshkey_to_base64(host_key, &mut keytext);
        if r != 0 as libc::c_int {
            sshfatal(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"load_hostkeys_command\0",
                ))
                .as_ptr(),
                858 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"sshkey_to_base64 failed\0" as *const u8 as *const libc::c_char,
            );
        }
    }
    osigchld = crate::misc::ssh_signal(17 as libc::c_int, None);
    if argv_split(command_template, &mut ac, &mut av, 0 as libc::c_int) != 0 as libc::c_int {
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"load_hostkeys_command\0"))
                .as_ptr(),
            869 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s \"%s\" contains invalid quotes\0" as *const u8 as *const libc::c_char,
            tag,
            command_template,
        );
    } else if ac == 0 as libc::c_int {
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"load_hostkeys_command\0"))
                .as_ptr(),
            874 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"%s \"%s\" yielded no arguments\0" as *const u8 as *const libc::c_char,
            tag,
            command_template,
        );
    } else {
        i = 1 as libc::c_int;
        while i < ac {
            tmp = percent_dollar_expand(
                *av.offset(i as isize),
                b"C\0" as *const u8 as *const libc::c_char,
                (*cinfo).conn_hash_hex,
                b"L\0" as *const u8 as *const libc::c_char,
                (*cinfo).shorthost,
                b"i\0" as *const u8 as *const libc::c_char,
                (*cinfo).uidstr,
                b"k\0" as *const u8 as *const libc::c_char,
                (*cinfo).keyalias,
                b"l\0" as *const u8 as *const libc::c_char,
                (*cinfo).thishost,
                b"n\0" as *const u8 as *const libc::c_char,
                (*cinfo).host_arg,
                b"p\0" as *const u8 as *const libc::c_char,
                (*cinfo).portstr,
                b"d\0" as *const u8 as *const libc::c_char,
                (*cinfo).homedir,
                b"h\0" as *const u8 as *const libc::c_char,
                (*cinfo).remhost,
                b"r\0" as *const u8 as *const libc::c_char,
                (*cinfo).remuser,
                b"u\0" as *const u8 as *const libc::c_char,
                (*cinfo).locuser,
                b"H\0" as *const u8 as *const libc::c_char,
                hostfile_hostname,
                b"I\0" as *const u8 as *const libc::c_char,
                invocation,
                b"t\0" as *const u8 as *const libc::c_char,
                if host_key.is_null() {
                    b"NONE\0" as *const u8 as *const libc::c_char
                } else {
                    sshkey_ssh_name(host_key)
                },
                b"f\0" as *const u8 as *const libc::c_char,
                if key_fp.is_null() {
                    b"NONE\0" as *const u8 as *const libc::c_char
                } else {
                    key_fp as *const libc::c_char
                },
                b"K\0" as *const u8 as *const libc::c_char,
                if keytext.is_null() {
                    b"NONE\0" as *const u8 as *const libc::c_char
                } else {
                    keytext as *const libc::c_char
                },
                0 as *mut libc::c_void as *mut libc::c_char,
            );
            if tmp.is_null() {
                sshfatal(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"load_hostkeys_command\0",
                    ))
                    .as_ptr(),
                    887 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"percent_expand failed\0" as *const u8 as *const libc::c_char,
                );
            }
            libc::free(*av.offset(i as isize) as *mut libc::c_void);
            let ref mut fresh0 = *av.offset(i as isize);
            *fresh0 = tmp;
            i += 1;
            i;
        }
        command = argv_assemble(ac, av);
        pid = subprocess(
            tag,
            command,
            ac,
            av,
            &mut f,
            ((1 as libc::c_int) << 1 as libc::c_int
                | (1 as libc::c_int) << 3 as libc::c_int
                | (1 as libc::c_int) << 4 as libc::c_int) as u_int,
            0 as *mut libc::passwd,
            None,
            None,
        );
        if !(pid == 0 as libc::c_int) {
            load_hostkeys_file(
                hostkeys,
                hostfile_hostname,
                tag,
                f,
                1 as libc::c_int as u_int,
            );
            if exited_cleanly(pid, tag, command, 0 as libc::c_int) != 0 as libc::c_int {
                sshfatal(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"load_hostkeys_command\0",
                    ))
                    .as_ptr(),
                    902 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"KnownHostsCommand failed\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }
    if !f.is_null() {
        fclose(f);
    }
    crate::misc::ssh_signal(17 as libc::c_int, osigchld);
    i = 0 as libc::c_int;
    while i < ac {
        libc::free(*av.offset(i as isize) as *mut libc::c_void);
        i += 1;
        i;
    }
    libc::free(av as *mut libc::c_void);
    libc::free(tag as *mut libc::c_void);
    libc::free(command as *mut libc::c_void);
    libc::free(key_fp as *mut libc::c_void);
    libc::free(keytext as *mut libc::c_void);
}
unsafe extern "C" fn check_host_key(
    mut hostname: *mut libc::c_char,
    mut cinfo: *const ssh_conn_info,
    mut hostaddr: *mut sockaddr,
    mut port: u_short,
    mut host_key: *mut crate::sshkey::sshkey,
    mut readonly: libc::c_int,
    mut clobber_port: libc::c_int,
    mut user_hostfiles: *mut *mut libc::c_char,
    mut num_user_hostfiles: u_int,
    mut system_hostfiles: *mut *mut libc::c_char,
    mut num_system_hostfiles: u_int,
    mut hostfile_command: *const libc::c_char,
) -> libc::c_int {
    let mut current_block: u64;
    let mut host_status: HostStatus = 4294967295 as HostStatus;
    let mut ip_status: HostStatus = 4294967295 as HostStatus;
    let mut raw_key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut ip: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut hostline: [libc::c_char; 1000] = [0; 1000];
    let mut hostp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ra: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut msg: [libc::c_char; 1024] = [0; 1024];
    let mut type_0: *const libc::c_char = 0 as *const libc::c_char;
    let mut fail_reason: *const libc::c_char = 0 as *const libc::c_char;
    let mut host_found: *const hostkey_entry = 0 as *const hostkey_entry;
    let mut ip_found: *const hostkey_entry = 0 as *const hostkey_entry;
    let mut len: libc::c_int = 0;
    let mut cancelled_forwarding: libc::c_int = 0 as libc::c_int;
    let mut confirmed: libc::c_int = 0;
    let mut local: libc::c_int = sockaddr_is_local(hostaddr);
    let mut r: libc::c_int = 0;
    let mut want_cert: libc::c_int = sshkey_is_cert(host_key);
    let mut host_ip_differ: libc::c_int = 0 as libc::c_int;
    let mut hostkey_trusted: libc::c_int = 0 as libc::c_int;
    let mut host_hostkeys: *mut hostkeys = 0 as *mut hostkeys;
    let mut ip_hostkeys: *mut hostkeys = 0 as *mut hostkeys;
    let mut i: u_int = 0;
    if options.no_host_authentication_for_localhost == 1 as libc::c_int
        && local != 0
        && (options.host_key_alias).is_null()
    {
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"check_host_key\0"))
                .as_ptr(),
            957 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"Forcing accepting of host key for loopback/localhost.\0" as *const u8
                as *const libc::c_char,
        );
        options.update_hostkeys = 0 as libc::c_int;
        return 0 as libc::c_int;
    }
    if strcspn(
        hostname,
        b"@?*#[]|''\"\\\0" as *const u8 as *const libc::c_char,
    ) != strlen(hostname)
    {
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"check_host_key\0"))
                .as_ptr(),
            969 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"invalid hostname \"%s\"; will not record: %s\0" as *const u8 as *const libc::c_char,
            hostname,
            fail_reason,
        );
        readonly = 1 as libc::c_int;
    }
    get_hostfile_hostname_ipaddr(
        hostname,
        hostaddr,
        (if clobber_port != 0 {
            0 as libc::c_int
        } else {
            port as libc::c_int
        }) as u_short,
        &mut host,
        &mut ip,
    );
    if options.check_host_ip != 0
        && (local != 0
            || libc::strcmp(hostname, ip) == 0 as libc::c_int
            || !(options.proxy_command).is_null())
    {
        options.check_host_ip = 0 as libc::c_int;
    }
    host_hostkeys = init_hostkeys();
    i = 0 as libc::c_int as u_int;
    while i < num_user_hostfiles {
        load_hostkeys(
            host_hostkeys,
            host,
            *user_hostfiles.offset(i as isize),
            0 as libc::c_int as u_int,
        );
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < num_system_hostfiles {
        load_hostkeys(
            host_hostkeys,
            host,
            *system_hostfiles.offset(i as isize),
            0 as libc::c_int as u_int,
        );
        i = i.wrapping_add(1);
        i;
    }
    if !hostfile_command.is_null() && clobber_port == 0 {
        load_hostkeys_command(
            host_hostkeys,
            hostfile_command,
            b"HOSTNAME\0" as *const u8 as *const libc::c_char,
            cinfo,
            host_key,
            host,
        );
    }
    ip_hostkeys = 0 as *mut hostkeys;
    if want_cert == 0 && options.check_host_ip != 0 {
        ip_hostkeys = init_hostkeys();
        i = 0 as libc::c_int as u_int;
        while i < num_user_hostfiles {
            load_hostkeys(
                ip_hostkeys,
                ip,
                *user_hostfiles.offset(i as isize),
                0 as libc::c_int as u_int,
            );
            i = i.wrapping_add(1);
            i;
        }
        i = 0 as libc::c_int as u_int;
        while i < num_system_hostfiles {
            load_hostkeys(
                ip_hostkeys,
                ip,
                *system_hostfiles.offset(i as isize),
                0 as libc::c_int as u_int,
            );
            i = i.wrapping_add(1);
            i;
        }
        if !hostfile_command.is_null() && clobber_port == 0 {
            load_hostkeys_command(
                ip_hostkeys,
                hostfile_command,
                b"ADDRESS\0" as *const u8 as *const libc::c_char,
                cinfo,
                host_key,
                ip,
            );
        }
    }
    loop {
        want_cert = sshkey_is_cert(host_key);
        type_0 = sshkey_type(host_key);
        host_status = check_key_in_hostkeys(host_hostkeys, host_key, &mut host_found);
        if readonly == 0
            && (num_user_hostfiles == 0 as libc::c_int as libc::c_uint
                || !host_found.is_null() && (*host_found).note != 0 as libc::c_int as libc::c_uint)
        {
            readonly = 1 as libc::c_int;
        }
        if want_cert == 0 && !ip_hostkeys.is_null() {
            ip_status = check_key_in_hostkeys(ip_hostkeys, host_key, &mut ip_found);
            if host_status as libc::c_uint == HOST_CHANGED as libc::c_int as libc::c_uint
                && (ip_status as libc::c_uint != HOST_CHANGED as libc::c_int as libc::c_uint
                    || !ip_found.is_null() && sshkey_equal((*ip_found).key, (*host_found).key) == 0)
            {
                host_ip_differ = 1 as libc::c_int;
            }
        } else {
            ip_status = host_status;
        }
        match host_status as libc::c_uint {
            0 => {
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"check_host_key\0",
                    ))
                    .as_ptr(),
                    1051 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"Host '%.200s' is known and matches the %s host %s.\0" as *const u8
                        as *const libc::c_char,
                    host,
                    type_0,
                    if want_cert != 0 {
                        b"certificate\0" as *const u8 as *const libc::c_char
                    } else {
                        b"key\0" as *const u8 as *const libc::c_char
                    },
                );
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"check_host_key\0",
                    ))
                    .as_ptr(),
                    1053 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"Found %s in %s:%lu\0" as *const u8 as *const libc::c_char,
                    if want_cert != 0 {
                        b"CA key\0" as *const u8 as *const libc::c_char
                    } else {
                        b"key\0" as *const u8 as *const libc::c_char
                    },
                    (*host_found).file,
                    (*host_found).line,
                );
                if want_cert != 0 {
                    if sshkey_cert_check_host(
                        host_key,
                        if (options.host_key_alias).is_null() {
                            hostname
                        } else {
                            options.host_key_alias
                        },
                        0 as libc::c_int,
                        options.ca_sign_algorithms,
                        &mut fail_reason,
                    ) != 0 as libc::c_int
                    {
                        crate::log::sshlog(
                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"check_host_key\0",
                            ))
                            .as_ptr(),
                            1059 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s\0" as *const u8 as *const libc::c_char,
                            fail_reason,
                        );
                        current_block = 16170235306303725311;
                    } else {
                        if options.update_hostkeys != 0 as libc::c_int {
                            options.update_hostkeys = 0 as libc::c_int;
                            crate::log::sshlog(
                                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                    b"check_host_key\0",
                                ))
                                .as_ptr(),
                                1069 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG3,
                                0 as *const libc::c_char,
                                b"certificate host key in use; disabling UpdateHostkeys\0"
                                    as *const u8
                                    as *const libc::c_char,
                            );
                        }
                        current_block = 1423531122933789233;
                    }
                } else {
                    current_block = 1423531122933789233;
                }
                match current_block {
                    16170235306303725311 => {}
                    _ => {
                        if options.update_hostkeys != 0 as libc::c_int
                            && (path_in_hostfiles(
                                (*host_found).file,
                                system_hostfiles,
                                num_system_hostfiles,
                            ) != 0
                                || ip_status as libc::c_uint
                                    == HOST_OK as libc::c_int as libc::c_uint
                                    && !ip_found.is_null()
                                    && path_in_hostfiles(
                                        (*ip_found).file,
                                        system_hostfiles,
                                        num_system_hostfiles,
                                    ) != 0)
                        {
                            options.update_hostkeys = 0 as libc::c_int;
                            crate::log::sshlog(
                                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<
                                    &[u8; 15],
                                    &[libc::c_char; 15],
                                >(b"check_host_key\0"))
                                    .as_ptr(),
                                1081 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG3,
                                0 as *const libc::c_char,
                                b"host key found in GlobalKnownHostsFile; disabling UpdateHostkeys\0"
                                    as *const u8 as *const libc::c_char,
                            );
                        }
                        if options.update_hostkeys != 0 as libc::c_int && (*host_found).note != 0 {
                            options.update_hostkeys = 0 as libc::c_int;
                            crate::log::sshlog(
                                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                    b"check_host_key\0",
                                ))
                                .as_ptr(),
                                1086 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG3,
                                0 as *const libc::c_char,
                                b"host key found via KnownHostsCommand; disabling UpdateHostkeys\0"
                                    as *const u8
                                    as *const libc::c_char,
                            );
                        }
                        if options.check_host_ip != 0
                            && ip_status as libc::c_uint == HOST_NEW as libc::c_int as libc::c_uint
                        {
                            if readonly != 0 || want_cert != 0 {
                                crate::log::sshlog(
                                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<
                                        &[u8; 15],
                                        &[libc::c_char; 15],
                                    >(b"check_host_key\0"))
                                        .as_ptr(),
                                    1092 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_INFO,
                                    0 as *const libc::c_char,
                                    b"%s host key for IP address '%.128s' not in list of known hosts.\0"
                                        as *const u8 as *const libc::c_char,
                                    type_0,
                                    ip,
                                );
                            } else if add_host_to_hostfile(
                                *user_hostfiles.offset(0 as libc::c_int as isize),
                                ip,
                                host_key,
                                options.hash_known_hosts,
                            ) == 0
                            {
                                crate::log::sshlog(
                                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<
                                        &[u8; 15],
                                        &[libc::c_char; 15],
                                    >(b"check_host_key\0"))
                                        .as_ptr(),
                                    1098 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_INFO,
                                    0 as *const libc::c_char,
                                    b"Failed to add the %s host key for IP address '%.128s' to the list of known hosts (%.500s).\0"
                                        as *const u8 as *const libc::c_char,
                                    type_0,
                                    ip,
                                    *user_hostfiles.offset(0 as libc::c_int as isize),
                                );
                            } else {
                                crate::log::sshlog(
                                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<
                                        &[u8; 15],
                                        &[libc::c_char; 15],
                                    >(b"check_host_key\0"))
                                        .as_ptr(),
                                    1102 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_INFO,
                                    0 as *const libc::c_char,
                                    b"Warning: Permanently added the %s host key for IP address '%.128s' to the list of known hosts.\0"
                                        as *const u8 as *const libc::c_char,
                                    type_0,
                                    ip,
                                );
                            }
                        } else if options.visual_host_key != 0 {
                            fp = sshkey_fingerprint(
                                host_key,
                                options.fingerprint_hash,
                                SSH_FP_DEFAULT,
                            );
                            ra = sshkey_fingerprint(
                                host_key,
                                options.fingerprint_hash,
                                SSH_FP_RANDOMART,
                            );
                            if fp.is_null() || ra.is_null() {
                                sshfatal(
                                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                        b"check_host_key\0",
                                    ))
                                    .as_ptr(),
                                    1109 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_FATAL,
                                    0 as *const libc::c_char,
                                    b"sshkey_fingerprint failed\0" as *const u8
                                        as *const libc::c_char,
                                );
                            }
                            crate::log::sshlog(
                                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                    b"check_host_key\0",
                                ))
                                .as_ptr(),
                                1110 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_INFO,
                                0 as *const libc::c_char,
                                b"Host key fingerprint is %s\n%s\0" as *const u8
                                    as *const libc::c_char,
                                fp,
                                ra,
                            );
                            libc::free(ra as *mut libc::c_void);
                            libc::free(fp as *mut libc::c_void);
                        }
                        hostkey_trusted = 1 as libc::c_int;
                        current_block = 1918110639124887667;
                    }
                }
            }
            1 => {
                if (options.host_key_alias).is_null()
                    && port as libc::c_int != 0 as libc::c_int
                    && port as libc::c_int != 22 as libc::c_int
                    && clobber_port == 0
                {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"check_host_key\0",
                        ))
                        .as_ptr(),
                        1119 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"checking without port identifier\0" as *const u8 as *const libc::c_char,
                    );
                    if check_host_key(
                        hostname,
                        cinfo,
                        hostaddr,
                        0 as libc::c_int as u_short,
                        host_key,
                        2 as libc::c_int,
                        1 as libc::c_int,
                        user_hostfiles,
                        num_user_hostfiles,
                        system_hostfiles,
                        num_system_hostfiles,
                        hostfile_command,
                    ) == 0 as libc::c_int
                    {
                        crate::log::sshlog(
                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"check_host_key\0",
                            ))
                            .as_ptr(),
                            1125 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_DEBUG1,
                            0 as *const libc::c_char,
                            b"found matching key w/out port\0" as *const u8 as *const libc::c_char,
                        );
                        current_block = 1918110639124887667;
                    } else {
                        current_block = 3229571381435211107;
                    }
                } else {
                    current_block = 3229571381435211107;
                }
                match current_block {
                    1918110639124887667 => {}
                    _ => {
                        if readonly != 0 || want_cert != 0 {
                            current_block = 16170235306303725311;
                        } else if options.strict_host_key_checking == 2 as libc::c_int {
                            crate::log::sshlog(
                                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<
                                    &[u8; 15],
                                    &[libc::c_char; 15],
                                >(b"check_host_key\0"))
                                    .as_ptr(),
                                1140 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"No %s host key is known for %.200s and you have requested strict checking.\0"
                                    as *const u8 as *const libc::c_char,
                                type_0,
                                host,
                            );
                            current_block = 16170235306303725311;
                        } else {
                            if options.strict_host_key_checking == 3 as libc::c_int {
                                let mut msg1: *mut libc::c_char = 0 as *mut libc::c_char;
                                let mut msg2: *mut libc::c_char = 0 as *mut libc::c_char;
                                crate::xmalloc::xasprintf(
                                    &mut msg1 as *mut *mut libc::c_char,
                                    b"The authenticity of host '%.200s (%s)' can't be established\0"
                                        as *const u8
                                        as *const libc::c_char,
                                    host,
                                    ip,
                                );
                                if show_other_keys(host_hostkeys, host_key) != 0 {
                                    xextendf(
                                        &mut msg1 as *mut *mut libc::c_char,
                                        b"\n\0" as *const u8 as *const libc::c_char,
                                        b"but keys of different type are already known for this host.\0"
                                            as *const u8 as *const libc::c_char,
                                    );
                                } else {
                                    xextendf(
                                        &mut msg1 as *mut *mut libc::c_char,
                                        b"\0" as *const u8 as *const libc::c_char,
                                        b".\0" as *const u8 as *const libc::c_char,
                                    );
                                }
                                fp = sshkey_fingerprint(
                                    host_key,
                                    options.fingerprint_hash,
                                    SSH_FP_DEFAULT,
                                );
                                ra = sshkey_fingerprint(
                                    host_key,
                                    options.fingerprint_hash,
                                    SSH_FP_RANDOMART,
                                );
                                if fp.is_null() || ra.is_null() {
                                    sshfatal(
                                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                            b"check_host_key\0",
                                        ))
                                        .as_ptr(),
                                        1160 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_FATAL,
                                        0 as *const libc::c_char,
                                        b"sshkey_fingerprint failed\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                }
                                xextendf(
                                    &mut msg1 as *mut *mut libc::c_char,
                                    b"\n\0" as *const u8 as *const libc::c_char,
                                    b"%s key fingerprint is %s.\0" as *const u8
                                        as *const libc::c_char,
                                    type_0,
                                    fp,
                                );
                                if options.visual_host_key != 0 {
                                    xextendf(
                                        &mut msg1 as *mut *mut libc::c_char,
                                        b"\n\0" as *const u8 as *const libc::c_char,
                                        b"%s\0" as *const u8 as *const libc::c_char,
                                        ra,
                                    );
                                }
                                if options.verify_host_key_dns != 0 {
                                    xextendf(
                                        &mut msg1 as *mut *mut libc::c_char,
                                        b"\n\0" as *const u8 as *const libc::c_char,
                                        b"%s host key fingerprint found in DNS.\0" as *const u8
                                            as *const libc::c_char,
                                        if matching_host_key_dns != 0 {
                                            b"Matching\0" as *const u8 as *const libc::c_char
                                        } else {
                                            b"No matching\0" as *const u8 as *const libc::c_char
                                        },
                                    );
                                }
                                msg2 = other_hostkeys_message(
                                    host,
                                    ip,
                                    host_key,
                                    user_hostfiles,
                                    num_user_hostfiles,
                                    system_hostfiles,
                                    num_system_hostfiles,
                                );
                                if !msg2.is_null() {
                                    xextendf(
                                        &mut msg1 as *mut *mut libc::c_char,
                                        b"\n\0" as *const u8 as *const libc::c_char,
                                        b"%s\0" as *const u8 as *const libc::c_char,
                                        msg2,
                                    );
                                }
                                xextendf(
                                    &mut msg1 as *mut *mut libc::c_char,
                                    b"\n\0" as *const u8 as *const libc::c_char,
                                    b"Are you sure you want to continue connecting (yes/no/[fingerprint])? \0"
                                        as *const u8 as *const libc::c_char,
                                );
                                confirmed = confirm(msg1, fp);
                                libc::free(ra as *mut libc::c_void);
                                libc::free(fp as *mut libc::c_void);
                                libc::free(msg1 as *mut libc::c_void);
                                libc::free(msg2 as *mut libc::c_void);
                                if confirmed == 0 {
                                    current_block = 16170235306303725311;
                                } else {
                                    hostkey_trusted = 1 as libc::c_int;
                                    current_block = 16463303006880176998;
                                }
                            } else {
                                current_block = 16463303006880176998;
                            }
                            match current_block {
                                16170235306303725311 => {}
                                _ => {
                                    if options.check_host_ip != 0
                                        && ip_status as libc::c_uint
                                            == HOST_NEW as libc::c_int as libc::c_uint
                                    {
                                        libc::snprintf(
                                            hostline.as_mut_ptr(),
                                            ::core::mem::size_of::<[libc::c_char; 1000]>() as usize,
                                            b"%s,%s\0" as *const u8 as *const libc::c_char,
                                            host,
                                            ip,
                                        );
                                        hostp = hostline.as_mut_ptr();
                                        if options.hash_known_hosts != 0 {
                                            r = (add_host_to_hostfile(
                                                *user_hostfiles.offset(0 as libc::c_int as isize),
                                                host,
                                                host_key,
                                                options.hash_known_hosts,
                                            ) != 0
                                                && add_host_to_hostfile(
                                                    *user_hostfiles
                                                        .offset(0 as libc::c_int as isize),
                                                    ip,
                                                    host_key,
                                                    options.hash_known_hosts,
                                                ) != 0)
                                                as libc::c_int;
                                        } else {
                                            r = add_host_to_hostfile(
                                                *user_hostfiles.offset(0 as libc::c_int as isize),
                                                hostline.as_mut_ptr(),
                                                host_key,
                                                options.hash_known_hosts,
                                            );
                                        }
                                    } else {
                                        r = add_host_to_hostfile(
                                            *user_hostfiles.offset(0 as libc::c_int as isize),
                                            host,
                                            host_key,
                                            options.hash_known_hosts,
                                        );
                                        hostp = host;
                                    }
                                    if r == 0 {
                                        crate::log::sshlog(
                                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 15],
                                                &[libc::c_char; 15],
                                            >(b"check_host_key\0"))
                                                .as_ptr(),
                                            1217 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_INFO,
                                            0 as *const libc::c_char,
                                            b"Failed to add the host to the list of known hosts (%.500s).\0"
                                                as *const u8 as *const libc::c_char,
                                            *user_hostfiles.offset(0 as libc::c_int as isize),
                                        );
                                    } else {
                                        crate::log::sshlog(
                                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 15],
                                                &[libc::c_char; 15],
                                            >(b"check_host_key\0"))
                                                .as_ptr(),
                                            1220 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_INFO,
                                            0 as *const libc::c_char,
                                            b"Warning: Permanently added '%.200s' (%s) to the list of known hosts.\0"
                                                as *const u8 as *const libc::c_char,
                                            hostp,
                                            type_0,
                                        );
                                    }
                                    current_block = 1918110639124887667;
                                }
                            }
                        }
                    }
                }
            }
            3 => {
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"check_host_key\0",
                    ))
                    .as_ptr(),
                    1223 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\0" as *const u8
                        as *const libc::c_char,
                );
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"check_host_key\0",
                    ))
                    .as_ptr(),
                    1224 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"@       WARNING: REVOKED HOST KEY DETECTED!               @\0" as *const u8
                        as *const libc::c_char,
                );
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"check_host_key\0",
                    ))
                    .as_ptr(),
                    1225 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\0" as *const u8
                        as *const libc::c_char,
                );
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"check_host_key\0",
                    ))
                    .as_ptr(),
                    1226 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"The %s host key for %s is marked as revoked.\0" as *const u8
                        as *const libc::c_char,
                    type_0,
                    host,
                );
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"check_host_key\0",
                    ))
                    .as_ptr(),
                    1227 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"This could mean that a stolen key is being used to\0" as *const u8
                        as *const libc::c_char,
                );
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"check_host_key\0",
                    ))
                    .as_ptr(),
                    1228 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"impersonate this host.\0" as *const u8 as *const libc::c_char,
                );
                if options.strict_host_key_checking != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<
                            &[u8; 15],
                            &[libc::c_char; 15],
                        >(b"check_host_key\0"))
                            .as_ptr(),
                        1237 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"%s host key for %.200s was revoked and you have requested strict checking.\0"
                            as *const u8 as *const libc::c_char,
                        type_0,
                        host,
                    );
                    current_block = 16170235306303725311;
                } else {
                    current_block = 18352186346566765615;
                }
            }
            2 => {
                if want_cert != 0 {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"check_host_key\0",
                        ))
                        .as_ptr(),
                        1251 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG1,
                        0 as *const libc::c_char,
                        b"Host certificate authority does not match %s in %s:%lu\0" as *const u8
                            as *const libc::c_char,
                        b"@cert-authority\0" as *const u8 as *const libc::c_char,
                        (*host_found).file,
                        (*host_found).line,
                    );
                    current_block = 16170235306303725311;
                } else if readonly == 2 as libc::c_int {
                    current_block = 16170235306303725311;
                } else {
                    if options.check_host_ip != 0 && host_ip_differ != 0 {
                        let mut key_msg: *mut libc::c_char = 0 as *mut libc::c_char;
                        if ip_status as libc::c_uint == HOST_NEW as libc::c_int as libc::c_uint {
                            key_msg = b"is unknown\0" as *const u8 as *const libc::c_char
                                as *mut libc::c_char;
                        } else if ip_status as libc::c_uint
                            == HOST_OK as libc::c_int as libc::c_uint
                        {
                            key_msg = b"is unchanged\0" as *const u8 as *const libc::c_char
                                as *mut libc::c_char;
                        } else {
                            key_msg = b"has a different value\0" as *const u8 as *const libc::c_char
                                as *mut libc::c_char;
                        }
                        crate::log::sshlog(
                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"check_host_key\0",
                            ))
                            .as_ptr(),
                            1264 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\0"
                                as *const u8 as *const libc::c_char,
                        );
                        crate::log::sshlog(
                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"check_host_key\0",
                            ))
                            .as_ptr(),
                            1265 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @\0"
                                as *const u8 as *const libc::c_char,
                        );
                        crate::log::sshlog(
                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"check_host_key\0",
                            ))
                            .as_ptr(),
                            1266 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\0"
                                as *const u8 as *const libc::c_char,
                        );
                        crate::log::sshlog(
                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"check_host_key\0",
                            ))
                            .as_ptr(),
                            1267 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"The %s host key for %s has changed,\0" as *const u8
                                as *const libc::c_char,
                            type_0,
                            host,
                        );
                        crate::log::sshlog(
                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"check_host_key\0",
                            ))
                            .as_ptr(),
                            1268 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"and the key for the corresponding IP address %s\0" as *const u8
                                as *const libc::c_char,
                            ip,
                        );
                        crate::log::sshlog(
                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"check_host_key\0",
                            ))
                            .as_ptr(),
                            1269 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"%s. This could either mean that\0" as *const u8
                                as *const libc::c_char,
                            key_msg,
                        );
                        crate::log::sshlog(
                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"check_host_key\0",
                            ))
                            .as_ptr(),
                            1270 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"DNS SPOOFING is happening or the IP address for the host\0"
                                as *const u8 as *const libc::c_char,
                        );
                        crate::log::sshlog(
                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"check_host_key\0",
                            ))
                            .as_ptr(),
                            1271 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"and its host key have changed at the same time.\0" as *const u8
                                as *const libc::c_char,
                        );
                        if ip_status as libc::c_uint != HOST_NEW as libc::c_int as libc::c_uint {
                            crate::log::sshlog(
                                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                    b"check_host_key\0",
                                ))
                                .as_ptr(),
                                1274 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"Offending key for IP in %s:%lu\0" as *const u8
                                    as *const libc::c_char,
                                (*ip_found).file,
                                (*ip_found).line,
                            );
                        }
                    }
                    warn_changed_key(host_key);
                    if num_user_hostfiles > 0 as libc::c_int as libc::c_uint
                        || num_system_hostfiles > 0 as libc::c_int as libc::c_uint
                    {
                        crate::log::sshlog(
                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                                b"check_host_key\0",
                            ))
                            .as_ptr(),
                            1281 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"Add correct host key in %.100s to get rid of this message.\0"
                                as *const u8 as *const libc::c_char,
                            if num_user_hostfiles > 0 as libc::c_int as libc::c_uint {
                                *user_hostfiles.offset(0 as libc::c_int as isize)
                            } else {
                                *system_hostfiles.offset(0 as libc::c_int as isize)
                            },
                        );
                    }
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"check_host_key\0",
                        ))
                        .as_ptr(),
                        1285 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Offending %s key in %s:%lu\0" as *const u8 as *const libc::c_char,
                        sshkey_type((*host_found).key),
                        (*host_found).file,
                        (*host_found).line,
                    );
                    if options.strict_host_key_checking != 0 as libc::c_int {
                        crate::log::sshlog(
                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<
                                &[u8; 15],
                                &[libc::c_char; 15],
                            >(b"check_host_key\0"))
                                .as_ptr(),
                            1294 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"Host key for %.200s has changed and you have requested strict checking.\0"
                                as *const u8 as *const libc::c_char,
                            host,
                        );
                        current_block = 16170235306303725311;
                    } else {
                        current_block = 18352186346566765615;
                    }
                }
            }
            4 => {
                sshfatal(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"check_host_key\0",
                    ))
                    .as_ptr(),
                    1360 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"internal error\0" as *const u8 as *const libc::c_char,
                );
            }
            _ => {
                current_block = 1918110639124887667;
            }
        }
        match current_block {
            18352186346566765615 => {
                if options.password_authentication != 0 {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"check_host_key\0",
                        ))
                        .as_ptr(),
                        1306 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Password authentication is disabled to avoid man-in-the-middle attacks.\0"
                            as *const u8 as *const libc::c_char,
                    );
                    options.password_authentication = 0 as libc::c_int;
                    cancelled_forwarding = 1 as libc::c_int;
                }
                if options.kbd_interactive_authentication != 0 {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<
                            &[u8; 15],
                            &[libc::c_char; 15],
                        >(b"check_host_key\0"))
                            .as_ptr(),
                        1312 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Keyboard-interactive authentication is disabled to avoid man-in-the-middle attacks.\0"
                            as *const u8 as *const libc::c_char,
                    );
                    options.kbd_interactive_authentication = 0 as libc::c_int;
                    cancelled_forwarding = 1 as libc::c_int;
                }
                if options.forward_agent != 0 {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"check_host_key\0",
                        ))
                        .as_ptr(),
                        1318 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Agent forwarding is disabled to avoid man-in-the-middle attacks.\0"
                            as *const u8 as *const libc::c_char,
                    );
                    options.forward_agent = 0 as libc::c_int;
                    cancelled_forwarding = 1 as libc::c_int;
                }
                if options.forward_x11 != 0 {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"check_host_key\0",
                        ))
                        .as_ptr(),
                        1324 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"X11 forwarding is disabled to avoid man-in-the-middle attacks.\0"
                            as *const u8 as *const libc::c_char,
                    );
                    options.forward_x11 = 0 as libc::c_int;
                    cancelled_forwarding = 1 as libc::c_int;
                }
                if options.num_local_forwards > 0 as libc::c_int
                    || options.num_remote_forwards > 0 as libc::c_int
                {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"check_host_key\0",
                        ))
                        .as_ptr(),
                        1331 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Port forwarding is disabled to avoid man-in-the-middle attacks.\0"
                            as *const u8 as *const libc::c_char,
                    );
                    options.num_remote_forwards = 0 as libc::c_int;
                    options.num_local_forwards = options.num_remote_forwards;
                    cancelled_forwarding = 1 as libc::c_int;
                }
                if options.tun_open != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"check_host_key\0",
                        ))
                        .as_ptr(),
                        1338 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Tunnel forwarding is disabled to avoid man-in-the-middle attacks.\0"
                            as *const u8 as *const libc::c_char,
                    );
                    options.tun_open = 0 as libc::c_int;
                    cancelled_forwarding = 1 as libc::c_int;
                }
                if options.update_hostkeys != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"check_host_key\0",
                        ))
                        .as_ptr(),
                        1344 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"UpdateHostkeys is disabled because the host key is not trusted.\0"
                            as *const u8 as *const libc::c_char,
                    );
                    options.update_hostkeys = 0 as libc::c_int;
                }
                if options.exit_on_forward_failure != 0 && cancelled_forwarding != 0 {
                    sshfatal(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"check_host_key\0",
                        ))
                        .as_ptr(),
                        1349 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Error: forwarding disabled due to host key check failure\0" as *const u8
                            as *const libc::c_char,
                    );
                }
                current_block = 1918110639124887667;
            }
            _ => {}
        }
        match current_block {
            1918110639124887667 => {
                if !(options.check_host_ip != 0
                    && host_status as libc::c_uint != HOST_CHANGED as libc::c_int as libc::c_uint
                    && ip_status as libc::c_uint == HOST_CHANGED as libc::c_int as libc::c_uint)
                {
                    break;
                }
                libc::snprintf(
                    msg.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
                    b"Warning: the %s host key for '%.200s' differs from the key for the IP address '%.128s'\nOffending key for IP in %s:%lu\0"
                        as *const u8 as *const libc::c_char,
                    type_0,
                    host,
                    ip,
                    (*ip_found).file,
                    (*ip_found).line,
                );
                if host_status as libc::c_uint == HOST_OK as libc::c_int as libc::c_uint {
                    len = strlen(msg.as_mut_ptr()) as libc::c_int;
                    libc::snprintf(
                        msg.as_mut_ptr().offset(len as isize),
                        (::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong)
                            .wrapping_sub(len as libc::c_ulong) as usize,
                        b"\nMatching host key in %s:%lu\0" as *const u8 as *const libc::c_char,
                        (*host_found).file,
                        (*host_found).line,
                    );
                }
                if options.strict_host_key_checking == 3 as libc::c_int {
                    strlcat(
                        msg.as_mut_ptr(),
                        b"\nAre you sure you want to continue connecting (yes/no)? \0" as *const u8
                            as *const libc::c_char,
                        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
                    );
                    if !(confirm(msg.as_mut_ptr(), 0 as *const libc::c_char) == 0) {
                        break;
                    }
                } else if options.strict_host_key_checking != 0 as libc::c_int {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"check_host_key\0",
                        ))
                        .as_ptr(),
                        1385 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        0 as *const libc::c_char,
                        b"%s\0" as *const u8 as *const libc::c_char,
                        msg.as_mut_ptr(),
                    );
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"check_host_key\0",
                        ))
                        .as_ptr(),
                        1386 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"Exiting, you have requested strict checking.\0" as *const u8
                            as *const libc::c_char,
                    );
                } else {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                            b"check_host_key\0",
                        ))
                        .as_ptr(),
                        1389 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        0 as *const libc::c_char,
                        b"%s\0" as *const u8 as *const libc::c_char,
                        msg.as_mut_ptr(),
                    );
                    break;
                }
            }
            _ => {}
        }
        if want_cert != 0
            && host_status as libc::c_uint != HOST_REVOKED as libc::c_int as libc::c_uint
        {
            crate::log::sshlog(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"check_host_key\0"))
                    .as_ptr(),
                1413 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"No matching CA found. Retry with plain key\0" as *const u8 as *const libc::c_char,
            );
            r = sshkey_from_private(host_key, &mut raw_key);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"check_host_key\0",
                    ))
                    .as_ptr(),
                    1415 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"decode key\0" as *const u8 as *const libc::c_char,
                );
            }
            r = sshkey_drop_cert(raw_key);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(
                        b"check_host_key\0",
                    ))
                    .as_ptr(),
                    1417 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"Couldn't drop certificate\0" as *const u8 as *const libc::c_char,
                );
            }
            host_key = raw_key;
        } else {
            crate::sshkey::sshkey_free(raw_key);
            libc::free(ip as *mut libc::c_void);
            libc::free(host as *mut libc::c_void);
            if !host_hostkeys.is_null() {
                free_hostkeys(host_hostkeys);
            }
            if !ip_hostkeys.is_null() {
                free_hostkeys(ip_hostkeys);
            }
            return -(1 as libc::c_int);
        }
    }
    if hostkey_trusted == 0 && options.update_hostkeys != 0 {
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"check_host_key\0"))
                .as_ptr(),
            1395 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"hostkey not known or explicitly trusted: disabling UpdateHostkeys\0" as *const u8
                as *const libc::c_char,
        );
        options.update_hostkeys = 0 as libc::c_int;
    }
    libc::free(ip as *mut libc::c_void);
    libc::free(host as *mut libc::c_void);
    if !host_hostkeys.is_null() {
        free_hostkeys(host_hostkeys);
    }
    if !ip_hostkeys.is_null() {
        free_hostkeys(ip_hostkeys);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn verify_host_key(
    mut host: *mut libc::c_char,
    mut hostaddr: *mut sockaddr,
    mut host_key: *mut crate::sshkey::sshkey,
    mut cinfo: *const ssh_conn_info,
) -> libc::c_int {
    let mut current_block: u64;
    let mut i: u_int = 0;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut flags: libc::c_int = 0 as libc::c_int;
    let mut valid: [libc::c_char; 64] = [0; 64];
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cafp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut plain: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    fp = sshkey_fingerprint(host_key, options.fingerprint_hash, SSH_FP_DEFAULT);
    if fp.is_null() {
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"verify_host_key\0"))
                .as_ptr(),
            1443 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"fingerprint host key\0" as *const u8 as *const libc::c_char,
        );
        r = -(1 as libc::c_int);
    } else {
        if sshkey_is_cert(host_key) != 0 {
            cafp = sshkey_fingerprint(
                (*(*host_key).cert).signature_key,
                options.fingerprint_hash,
                SSH_FP_DEFAULT,
            );
            if cafp.is_null() {
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"verify_host_key\0",
                    ))
                    .as_ptr(),
                    1451 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"fingerprint CA key\0" as *const u8 as *const libc::c_char,
                );
                r = -(1 as libc::c_int);
                current_block = 18082163382412822748;
            } else {
                sshkey_format_cert_validity(
                    (*host_key).cert,
                    valid.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
                );
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"verify_host_key\0",
                    ))
                    .as_ptr(),
                    1463 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_DEBUG1,
                    0 as *const libc::c_char,
                    b"Server host certificate: %s %s, serial %llu ID \"%s\" CA %s %s valid %s\0"
                        as *const u8 as *const libc::c_char,
                    sshkey_ssh_name(host_key),
                    fp,
                    (*(*host_key).cert).serial as libc::c_ulonglong,
                    (*(*host_key).cert).key_id,
                    sshkey_ssh_name((*(*host_key).cert).signature_key),
                    cafp,
                    valid.as_mut_ptr(),
                );
                i = 0 as libc::c_int as u_int;
                while i < (*(*host_key).cert).nprincipals {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"verify_host_key\0",
                        ))
                        .as_ptr(),
                        1466 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        0 as *const libc::c_char,
                        b"Server host certificate hostname: %s\0" as *const u8
                            as *const libc::c_char,
                        *((*(*host_key).cert).principals).offset(i as isize),
                    );
                    i = i.wrapping_add(1);
                    i;
                }
                current_block = 12349973810996921269;
            }
        } else {
            crate::log::sshlog(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"verify_host_key\0"))
                    .as_ptr(),
                1469 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"Server host key: %s %s\0" as *const u8 as *const libc::c_char,
                sshkey_ssh_name(host_key),
                fp,
            );
            current_block = 12349973810996921269;
        }
        match current_block {
            18082163382412822748 => {}
            _ => {
                if sshkey_equal(previous_host_key, host_key) != 0 {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"verify_host_key\0",
                        ))
                        .as_ptr(),
                        1474 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_DEBUG2,
                        0 as *const libc::c_char,
                        b"server host key %s %s matches cached key\0" as *const u8
                            as *const libc::c_char,
                        sshkey_type(host_key),
                        fp,
                    );
                    r = 0 as libc::c_int;
                } else {
                    if !(options.revoked_host_keys).is_null() {
                        r = sshkey_check_revoked(host_key, options.revoked_host_keys);
                        match r {
                            0 => {
                                current_block = 17478428563724192186;
                            }
                            -51 => {
                                current_block = 17454715328846399138;
                                match current_block {
                                    11540969074707162923 => {
                                        crate::log::sshlog(
                                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 16],
                                                &[libc::c_char; 16],
                                            >(b"verify_host_key\0"))
                                                .as_ptr(),
                                            1494 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            ssh_err(r),
                                            b"Error checking host key %s %s in revoked keys file %s\0"
                                                as *const u8 as *const libc::c_char,
                                            sshkey_type(host_key),
                                            fp,
                                            options.revoked_host_keys,
                                        );
                                        r = -(1 as libc::c_int);
                                    }
                                    _ => {
                                        crate::log::sshlog(
                                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 16],
                                                &[libc::c_char; 16],
                                            >(
                                                b"verify_host_key\0"
                                            ))
                                            .as_ptr(),
                                            1488 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"Host key %s %s revoked by file %s\0" as *const u8
                                                as *const libc::c_char,
                                            sshkey_type(host_key),
                                            fp,
                                            options.revoked_host_keys,
                                        );
                                        r = -(1 as libc::c_int);
                                    }
                                }
                                current_block = 18082163382412822748;
                            }
                            _ => {
                                current_block = 11540969074707162923;
                                match current_block {
                                    11540969074707162923 => {
                                        crate::log::sshlog(
                                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 16],
                                                &[libc::c_char; 16],
                                            >(b"verify_host_key\0"))
                                                .as_ptr(),
                                            1494 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            ssh_err(r),
                                            b"Error checking host key %s %s in revoked keys file %s\0"
                                                as *const u8 as *const libc::c_char,
                                            sshkey_type(host_key),
                                            fp,
                                            options.revoked_host_keys,
                                        );
                                        r = -(1 as libc::c_int);
                                    }
                                    _ => {
                                        crate::log::sshlog(
                                            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 16],
                                                &[libc::c_char; 16],
                                            >(
                                                b"verify_host_key\0"
                                            ))
                                            .as_ptr(),
                                            1488 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"Host key %s %s revoked by file %s\0" as *const u8
                                                as *const libc::c_char,
                                            sshkey_type(host_key),
                                            fp,
                                            options.revoked_host_keys,
                                        );
                                        r = -(1 as libc::c_int);
                                    }
                                }
                                current_block = 18082163382412822748;
                            }
                        }
                    } else {
                        current_block = 17478428563724192186;
                    }
                    match current_block {
                        18082163382412822748 => {}
                        _ => {
                            if options.verify_host_key_dns != 0 {
                                r = sshkey_from_private(host_key, &mut plain);
                                if r != 0 as libc::c_int {
                                    current_block = 18082163382412822748;
                                } else {
                                    if sshkey_is_cert(plain) != 0 {
                                        sshkey_drop_cert(plain);
                                    }
                                    if verify_host_key_dns(host, hostaddr, plain, &mut flags)
                                        == 0 as libc::c_int
                                    {
                                        if flags & 0x1 as libc::c_int != 0 {
                                            if options.verify_host_key_dns == 1 as libc::c_int
                                                && flags & 0x2 as libc::c_int != 0
                                                && flags & 0x4 as libc::c_int != 0
                                            {
                                                r = 0 as libc::c_int;
                                                current_block = 18082163382412822748;
                                            } else {
                                                if flags & 0x2 as libc::c_int != 0 {
                                                    matching_host_key_dns = 1 as libc::c_int;
                                                } else {
                                                    warn_changed_key(plain);
                                                    crate::log::sshlog(
                                                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                                                        (*::core::mem::transmute::<
                                                            &[u8; 16],
                                                            &[libc::c_char; 16],
                                                        >(b"verify_host_key\0"))
                                                            .as_ptr(),
                                                        1523 as libc::c_int,
                                                        0 as libc::c_int,
                                                        SYSLOG_LEVEL_ERROR,
                                                        0 as *const libc::c_char,
                                                        b"Update the SSHFP RR in DNS with the new host key to get rid of this message.\0"
                                                            as *const u8 as *const libc::c_char,
                                                    );
                                                }
                                                current_block = 4090602189656566074;
                                            }
                                        } else {
                                            current_block = 4090602189656566074;
                                        }
                                    } else {
                                        current_block = 4090602189656566074;
                                    }
                                }
                            } else {
                                current_block = 4090602189656566074;
                            }
                            match current_block {
                                18082163382412822748 => {}
                                _ => {
                                    r = check_host_key(
                                        host,
                                        cinfo,
                                        hostaddr,
                                        options.port as u_short,
                                        host_key,
                                        0 as libc::c_int,
                                        0 as libc::c_int,
                                        (options.user_hostfiles).as_mut_ptr(),
                                        options.num_user_hostfiles,
                                        (options.system_hostfiles).as_mut_ptr(),
                                        options.num_system_hostfiles,
                                        options.known_hosts_command,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    crate::sshkey::sshkey_free(plain);
    libc::free(fp as *mut libc::c_void);
    libc::free(cafp as *mut libc::c_void);
    if r == 0 as libc::c_int && !host_key.is_null() {
        crate::sshkey::sshkey_free(previous_host_key);
        r = sshkey_from_private(host_key, &mut previous_host_key);
    }
    return r;
}
pub unsafe extern "C" fn ssh_login(
    mut ssh: *mut ssh,
    mut sensitive: *mut Sensitive,
    mut orighost: *const libc::c_char,
    mut hostaddr: *mut sockaddr,
    mut port: u_short,
    mut pw: *mut libc::passwd,
    mut timeout_ms: libc::c_int,
    mut cinfo: *const ssh_conn_info,
) {
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut server_user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut local_user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    local_user = crate::xmalloc::xstrdup((*pw).pw_name);
    server_user = if !(options.user).is_null() {
        options.user
    } else {
        local_user
    };
    host = crate::xmalloc::xstrdup(orighost);
    lowercase(host);
    r = kex_exchange_identification(ssh, timeout_ms, 0 as *const libc::c_char);
    if r != 0 as libc::c_int {
        sshpkt_fatal(
            ssh,
            r,
            b"banner exchange\0" as *const u8 as *const libc::c_char,
        );
    }
    ssh_packet_set_nonblocking(ssh);
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 10], &[libc::c_char; 10]>(b"ssh_login\0")).as_ptr(),
        1577 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"Authenticating to %s:%d as '%s'\0" as *const u8 as *const libc::c_char,
        host,
        port as libc::c_int,
        server_user,
    );
    ssh_kex2(ssh, host, hostaddr, port, cinfo);
    ssh_userauth2(ssh, local_user, server_user, host, sensitive);
    libc::free(local_user as *mut libc::c_void);
    libc::free(host as *mut libc::c_void);
}
unsafe extern "C" fn show_other_keys(
    mut hostkeys: *mut hostkeys,
    mut key: *mut crate::sshkey::sshkey,
) -> libc::c_int {
    let mut type_0: [libc::c_int; 6] = [
        KEY_RSA as libc::c_int,
        KEY_DSA as libc::c_int,
        KEY_ECDSA as libc::c_int,
        KEY_ED25519 as libc::c_int,
        KEY_XMSS as libc::c_int,
        -(1 as libc::c_int),
    ];
    let mut i: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ra: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut found: *const hostkey_entry = 0 as *const hostkey_entry;
    i = 0 as libc::c_int;
    while type_0[i as usize] != -(1 as libc::c_int) {
        if !(type_0[i as usize] == (*key).type_0) {
            if !(lookup_key_in_hostkeys_by_type(
                hostkeys,
                type_0[i as usize],
                -(1 as libc::c_int),
                &mut found,
            ) == 0)
            {
                fp = sshkey_fingerprint((*found).key, options.fingerprint_hash, SSH_FP_DEFAULT);
                ra = sshkey_fingerprint((*found).key, options.fingerprint_hash, SSH_FP_RANDOMART);
                if fp.is_null() || ra.is_null() {
                    sshfatal(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"show_other_keys\0",
                        ))
                        .as_ptr(),
                        1611 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"sshkey_fingerprint fail\0" as *const u8 as *const libc::c_char,
                    );
                }
                crate::log::sshlog(
                    b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                        b"show_other_keys\0",
                    ))
                    .as_ptr(),
                    1617 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_INFO,
                    0 as *const libc::c_char,
                    b"WARNING: %s key found for host %s\nin %s:%lu\n%s key fingerprint %s.\0"
                        as *const u8 as *const libc::c_char,
                    sshkey_type((*found).key),
                    (*found).host,
                    (*found).file,
                    (*found).line,
                    sshkey_type((*found).key),
                    fp,
                );
                if options.visual_host_key != 0 {
                    crate::log::sshlog(
                        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(
                            b"show_other_keys\0",
                        ))
                        .as_ptr(),
                        1619 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_INFO,
                        0 as *const libc::c_char,
                        b"%s\0" as *const u8 as *const libc::c_char,
                        ra,
                    );
                }
                libc::free(ra as *mut libc::c_void);
                libc::free(fp as *mut libc::c_void);
                ret = 1 as libc::c_int;
            }
        }
        i += 1;
        i;
    }
    return ret;
}
unsafe extern "C" fn warn_changed_key(mut host_key: *mut crate::sshkey::sshkey) {
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    fp = sshkey_fingerprint(host_key, options.fingerprint_hash, SSH_FP_DEFAULT);
    if fp.is_null() {
        sshfatal(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"warn_changed_key\0"))
                .as_ptr(),
            1635 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"sshkey_fingerprint fail\0" as *const u8 as *const libc::c_char,
        );
    }
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"warn_changed_key\0")).as_ptr(),
        1637 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\0" as *const u8
            as *const libc::c_char,
    );
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"warn_changed_key\0")).as_ptr(),
        1638 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\0" as *const u8
            as *const libc::c_char,
    );
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"warn_changed_key\0")).as_ptr(),
        1639 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\0" as *const u8
            as *const libc::c_char,
    );
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"warn_changed_key\0")).as_ptr(),
        1640 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!\0" as *const u8
            as *const libc::c_char,
    );
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"warn_changed_key\0")).as_ptr(),
        1641 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"Someone could be eavesdropping on you right now (man-in-the-middle attack)!\0"
            as *const u8 as *const libc::c_char,
    );
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"warn_changed_key\0")).as_ptr(),
        1642 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"It is also possible that a host key has just been changed.\0" as *const u8
            as *const libc::c_char,
    );
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"warn_changed_key\0")).as_ptr(),
        1644 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"The fingerprint for the %s key sent by the remote host is\n%s.\0" as *const u8
            as *const libc::c_char,
        sshkey_type(host_key),
        fp,
    );
    crate::log::sshlog(
        b"sshconnect.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 17], &[libc::c_char; 17]>(b"warn_changed_key\0")).as_ptr(),
        1645 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"Please contact your system administrator.\0" as *const u8 as *const libc::c_char,
    );
    libc::free(fp as *mut libc::c_void);
}
pub unsafe extern "C" fn ssh_local_cmd(mut args: *const libc::c_char) -> libc::c_int {
    let mut shell: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pid: pid_t = 0;
    let mut status: libc::c_int = 0;
    let mut osighand: Option<unsafe extern "C" fn(libc::c_int) -> ()> = None;
    if options.permit_local_command == 0 || args.is_null() || *args == 0 {
        return 1 as libc::c_int;
    }
    shell = getenv(b"SHELL\0" as *const u8 as *const libc::c_char);
    if shell.is_null() || *shell as libc::c_int == '\0' as i32 {
        shell = b"/bin/sh\0" as *const u8 as *const libc::c_char as *mut libc::c_char;
    }
    osighand = crate::misc::ssh_signal(17 as libc::c_int, None);
    pid = libc::fork();
    if pid == 0 as libc::c_int {
        crate::misc::ssh_signal(13 as libc::c_int, None);
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ssh_local_cmd\0"))
                .as_ptr(),
            1672 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"Executing %s -c \"%s\"\0" as *const u8 as *const libc::c_char,
            shell,
            args,
        );
        execl(
            shell,
            shell,
            b"-c\0" as *const u8 as *const libc::c_char,
            args,
            0 as *mut libc::c_void as *mut libc::c_char,
        );
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ssh_local_cmd\0"))
                .as_ptr(),
            1675 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Couldn't execute %s -c \"%s\": %s\0" as *const u8 as *const libc::c_char,
            shell,
            args,
            libc::strerror(*libc::__errno_location()),
        );
        libc::_exit(1 as libc::c_int);
    } else if pid == -(1 as libc::c_int) {
        sshfatal(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ssh_local_cmd\0"))
                .as_ptr(),
            1678 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"libc::fork failed: %.100s\0" as *const u8 as *const libc::c_char,
            libc::strerror(*libc::__errno_location()),
        );
    }
    while libc::waitpid(pid, &mut status, 0 as libc::c_int) == -(1 as libc::c_int) {
        if *libc::__errno_location() != 4 as libc::c_int {
            sshfatal(
                b"sshconnect.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ssh_local_cmd\0"))
                    .as_ptr(),
                1681 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Couldn't wait for child: %s\0" as *const u8 as *const libc::c_char,
                libc::strerror(*libc::__errno_location()),
            );
        }
    }
    crate::misc::ssh_signal(17 as libc::c_int, osighand);
    if !(status & 0x7f as libc::c_int == 0 as libc::c_int) {
        return 1 as libc::c_int;
    }
    return (status & 0xff00 as libc::c_int) >> 8 as libc::c_int;
}
pub unsafe extern "C" fn maybe_add_key_to_agent(
    mut authfile: *const libc::c_char,
    mut private: *mut crate::sshkey::sshkey,
    mut comment: *const libc::c_char,
    mut _passphrase: *const libc::c_char,
) {
    let mut auth_sock: libc::c_int = -(1 as libc::c_int);
    let mut r: libc::c_int = 0;
    let mut skprovider: *const libc::c_char = 0 as *const libc::c_char;
    if options.add_keys_to_agent == 0 as libc::c_int {
        return;
    }
    r = ssh_get_authentication_socket(&mut auth_sock);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"maybe_add_key_to_agent\0",
            ))
            .as_ptr(),
            1701 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"no authentication agent, not adding key\0" as *const u8 as *const libc::c_char,
        );
        return;
    }
    if options.add_keys_to_agent == 2 as libc::c_int
        && ask_permission(
            b"Add key %s (%s) to agent?\0" as *const u8 as *const libc::c_char,
            authfile,
            comment,
        ) == 0
    {
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"maybe_add_key_to_agent\0",
            ))
            .as_ptr(),
            1707 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"user denied adding this key\0" as *const u8 as *const libc::c_char,
        );
        close(auth_sock);
        return;
    }
    if sshkey_is_sk(private) != 0 {
        skprovider = options.sk_provider;
    }
    r = ssh_add_identity_constrained(
        auth_sock,
        private,
        if comment.is_null() { authfile } else { comment },
        options.add_keys_to_agent_lifespan as u_int,
        (options.add_keys_to_agent == 3 as libc::c_int) as libc::c_int as u_int,
        0 as libc::c_int as u_int,
        skprovider,
        0 as *mut *mut dest_constraint,
        0 as libc::c_int as size_t,
    );
    if r == 0 as libc::c_int {
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"maybe_add_key_to_agent\0",
            ))
            .as_ptr(),
            1717 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"identity added to agent: %s\0" as *const u8 as *const libc::c_char,
            authfile,
        );
    } else {
        crate::log::sshlog(
            b"sshconnect.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"maybe_add_key_to_agent\0",
            ))
            .as_ptr(),
            1719 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"could not add identity to agent: %s (%d)\0" as *const u8 as *const libc::c_char,
            authfile,
            r,
        );
    }
    close(auth_sock);
}
