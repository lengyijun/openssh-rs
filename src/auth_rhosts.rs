use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn strcasecmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn stat(__file: *const libc::c_char, __buf: *mut stat) -> libc::c_int;
    fn fstat(__fd: libc::c_int, __buf: *mut stat) -> libc::c_int;
    fn __errno_location() -> *mut libc::c_int;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn innetgr(
        __netgroup: *const libc::c_char,
        __host: *const libc::c_char,
        __user: *const libc::c_char,
        __domain: *const libc::c_char,
    ) -> libc::c_int;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fdopen(__fd: libc::c_int, __modes: *const libc::c_char) -> *mut FILE;
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn fgets(__s: *mut libc::c_char, __n: libc::c_int, __stream: *mut FILE) -> *mut libc::c_char;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn free(_: *mut libc::c_void);
    fn temporarily_use_uid(_: *mut passwd);
    fn restore_uid();
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
    fn unset_nonblock(_: libc::c_int) -> libc::c_int;
    fn xasprintf(_: *mut *mut libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn auth_debug_add(fmt: *const libc::c_char, _: ...);
    static mut options: ServerOptions;
}
pub type __u_int = libc::c_uint;
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
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
pub type u_int = __u_int;
pub type mode_t = __mode_t;
pub type size_t = libc::c_ulong;
pub type int64_t = __int64_t;
pub type u_int64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct timespec {
    pub tv_sec: __time_t,
    pub tv_nsec: __syscall_slong_t,
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
pub struct stat {
    pub st_dev: __dev_t,
    pub st_ino: __ino_t,
    pub st_nlink: __nlink_t,
    pub st_mode: __mode_t,
    pub st_uid: __uid_t,
    pub st_gid: __gid_t,
    pub __pad0: libc::c_int,
    pub st_rdev: __dev_t,
    pub st_size: __off_t,
    pub st_blksize: __blksize_t,
    pub st_blocks: __blkcnt_t,
    pub st_atim: timespec,
    pub st_mtim: timespec,
    pub st_ctim: timespec,
    pub __glibc_reserved: [__syscall_slong_t; 3],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct passwd {
    pub pw_name: *mut libc::c_char,
    pub pw_passwd: *mut libc::c_char,
    pub pw_uid: __uid_t,
    pub pw_gid: __gid_t,
    pub pw_gecos: *mut libc::c_char,
    pub pw_dir: *mut libc::c_char,
    pub pw_shell: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
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
pub struct ForwardOptions {
    pub gateway_ports: libc::c_int,
    pub streamlocal_bind_mask: mode_t,
    pub streamlocal_bind_unlink: libc::c_int,
}
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
unsafe extern "C" fn check_rhosts_file(
    mut filename: *const libc::c_char,
    mut hostname: *const libc::c_char,
    mut ipaddr: *const libc::c_char,
    mut client_user: *const libc::c_char,
    mut server_user: *const libc::c_char,
) -> libc::c_int {
    let mut f: *mut FILE = 0 as *mut FILE;
    let mut buf: [libc::c_char; 1024] = [0; 1024];
    let mut fd: libc::c_int = 0;
    let mut st: stat = stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_mtim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_ctim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        __glibc_reserved: [0; 3],
    };
    fd = libc::open(filename, 0 as libc::c_int | 0o4000 as libc::c_int);
    if fd == -(1 as libc::c_int) {
        return 0 as libc::c_int;
    }
    if fstat(fd, &mut st) == -(1 as libc::c_int) {
        close(fd);
        return 0 as libc::c_int;
    }
    if !(st.st_mode & 0o170000 as libc::c_int as libc::c_uint
        == 0o100000 as libc::c_int as libc::c_uint)
    {
        sshlog(
            b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"check_rhosts_file\0"))
                .as_ptr(),
            77 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"User %s hosts file %s is not a regular file\0" as *const u8 as *const libc::c_char,
            server_user,
            filename,
        );
        close(fd);
        return 0 as libc::c_int;
    }
    unset_nonblock(fd);
    f = fdopen(fd, b"r\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        close(fd);
        return 0 as libc::c_int;
    }
    while !(fgets(
        buf.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong as libc::c_int,
        f,
    ))
    .is_null()
    {
        let mut hostbuf: [libc::c_char; 1024] = [0; 1024];
        let mut userbuf: [libc::c_char; 1024] = [0; 1024];
        let mut dummy: [libc::c_char; 1024] = [0; 1024];
        let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
        let mut negated: libc::c_int = 0;
        cp = buf.as_mut_ptr();
        while *cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32 {
            cp = cp.offset(1);
            cp;
        }
        if *cp as libc::c_int == '#' as i32 || *cp as libc::c_int == '\n' as i32 || *cp == 0 {
            continue;
        }
        if strncmp(
            cp,
            b"NO_PLUS\0" as *const u8 as *const libc::c_char,
            7 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            continue;
        }
        match sscanf(
            buf.as_mut_ptr(),
            b"%1023s %1023s %1023s\0" as *const u8 as *const libc::c_char,
            hostbuf.as_mut_ptr(),
            userbuf.as_mut_ptr(),
            dummy.as_mut_ptr(),
        ) {
            0 => {
                auth_debug_add(
                    b"Found empty line in %.100s.\0" as *const u8 as *const libc::c_char,
                    filename,
                );
                continue;
            }
            1 => {
                strlcpy(
                    userbuf.as_mut_ptr(),
                    server_user,
                    ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
                );
            }
            2 => {}
            3 => {
                auth_debug_add(
                    b"Found garbage in %.100s.\0" as *const u8 as *const libc::c_char,
                    filename,
                );
                continue;
            }
            _ => {
                continue;
            }
        }
        host = hostbuf.as_mut_ptr();
        user = userbuf.as_mut_ptr();
        negated = 0 as libc::c_int;
        if *host.offset(0 as libc::c_int as isize) as libc::c_int == '-' as i32 {
            negated = 1 as libc::c_int;
            host = host.offset(1);
            host;
        } else if *host.offset(0 as libc::c_int as isize) as libc::c_int == '+' as i32 {
            host = host.offset(1);
            host;
        }
        if *user.offset(0 as libc::c_int as isize) as libc::c_int == '-' as i32 {
            negated = 1 as libc::c_int;
            user = user.offset(1);
            user;
        } else if *user.offset(0 as libc::c_int as isize) as libc::c_int == '+' as i32 {
            user = user.offset(1);
            user;
        }
        if *host.offset(0 as libc::c_int as isize) == 0
            || *user.offset(0 as libc::c_int as isize) == 0
        {
            auth_debug_add(
                b"Ignoring wild host/user names in %.100s.\0" as *const u8 as *const libc::c_char,
                filename,
            );
        } else {
            if *host.offset(0 as libc::c_int as isize) as libc::c_int == '@' as i32 {
                if innetgr(
                    host.offset(1 as libc::c_int as isize),
                    hostname,
                    0 as *const libc::c_char,
                    0 as *const libc::c_char,
                ) == 0
                    && innetgr(
                        host.offset(1 as libc::c_int as isize),
                        ipaddr,
                        0 as *const libc::c_char,
                        0 as *const libc::c_char,
                    ) == 0
                {
                    continue;
                }
            } else if strcasecmp(host, hostname) != 0 && strcmp(host, ipaddr) != 0 as libc::c_int {
                continue;
            }
            if *user.offset(0 as libc::c_int as isize) as libc::c_int == '@' as i32 {
                if innetgr(
                    user.offset(1 as libc::c_int as isize),
                    0 as *const libc::c_char,
                    client_user,
                    0 as *const libc::c_char,
                ) == 0
                {
                    continue;
                }
            } else if strcmp(user, client_user) != 0 as libc::c_int {
                continue;
            }
            fclose(f);
            if negated != 0 {
                auth_debug_add(
                    b"Matched negative entry in %.100s.\0" as *const u8 as *const libc::c_char,
                    filename,
                );
                return 0 as libc::c_int;
            }
            return 1 as libc::c_int;
        }
    }
    fclose(f);
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn auth_rhosts2(
    mut pw: *mut passwd,
    mut client_user: *const libc::c_char,
    mut hostname: *const libc::c_char,
    mut ipaddr: *const libc::c_char,
) -> libc::c_int {
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut st: stat = stat {
        st_dev: 0,
        st_ino: 0,
        st_nlink: 0,
        st_mode: 0,
        st_uid: 0,
        st_gid: 0,
        __pad0: 0,
        st_rdev: 0,
        st_size: 0,
        st_blksize: 0,
        st_blocks: 0,
        st_atim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_mtim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        st_ctim: timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
        __glibc_reserved: [0; 3],
    };
    static mut rhosts_files: [*const libc::c_char; 3] = [
        b".shosts\0" as *const u8 as *const libc::c_char,
        b".rhosts\0" as *const u8 as *const libc::c_char,
        0 as *const libc::c_char,
    ];
    let mut rhosts_file_index: u_int = 0;
    let mut r: libc::c_int = 0;
    sshlog(
        b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"auth_rhosts2\0")).as_ptr(),
        202 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"clientuser %s hostname %s ipaddr %s\0" as *const u8 as *const libc::c_char,
        client_user,
        hostname,
        ipaddr,
    );
    temporarily_use_uid(pw);
    rhosts_file_index = 0 as libc::c_int as u_int;
    while !(rhosts_files[rhosts_file_index as usize]).is_null() {
        xasprintf(
            &mut path as *mut *mut libc::c_char,
            b"%s/%s\0" as *const u8 as *const libc::c_char,
            (*pw).pw_dir,
            rhosts_files[rhosts_file_index as usize],
        );
        r = stat(path, &mut st);
        free(path as *mut libc::c_void);
        if r >= 0 as libc::c_int {
            break;
        }
        rhosts_file_index = rhosts_file_index.wrapping_add(1);
        rhosts_file_index;
    }
    restore_uid();
    if (rhosts_files[rhosts_file_index as usize]).is_null()
        && stat(
            b"/etc/hosts.equiv\0" as *const u8 as *const libc::c_char,
            &mut st,
        ) == -(1 as libc::c_int)
        && stat(
            b"/usr/local/etc/shosts.equiv\0" as *const u8 as *const libc::c_char,
            &mut st,
        ) == -(1 as libc::c_int)
    {
        sshlog(
            b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"auth_rhosts2\0")).as_ptr(),
            232 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"no hosts access files exist\0" as *const u8 as *const libc::c_char,
        );
        return 0 as libc::c_int;
    }
    if (*pw).pw_uid == 0 as libc::c_int as libc::c_uint {
        sshlog(
            b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"auth_rhosts2\0")).as_ptr(),
            241 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"root user, ignoring system hosts files\0" as *const u8 as *const libc::c_char,
        );
    } else {
        if check_rhosts_file(
            b"/etc/hosts.equiv\0" as *const u8 as *const libc::c_char,
            hostname,
            ipaddr,
            client_user,
            (*pw).pw_name,
        ) != 0
        {
            auth_debug_add(
                b"Accepted for %.100s [%.100s] by /etc/hosts.equiv.\0" as *const u8
                    as *const libc::c_char,
                hostname,
                ipaddr,
            );
            return 1 as libc::c_int;
        }
        if check_rhosts_file(
            b"/usr/local/etc/shosts.equiv\0" as *const u8 as *const libc::c_char,
            hostname,
            ipaddr,
            client_user,
            (*pw).pw_name,
        ) != 0
        {
            auth_debug_add(
                b"Accepted for %.100s [%.100s] by %.100s.\0" as *const u8 as *const libc::c_char,
                hostname,
                ipaddr,
                b"/usr/local/etc/shosts.equiv\0" as *const u8 as *const libc::c_char,
            );
            return 1 as libc::c_int;
        }
    }
    if stat((*pw).pw_dir, &mut st) == -(1 as libc::c_int) {
        sshlog(
            b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"auth_rhosts2\0")).as_ptr(),
            263 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Rhosts authentication refused for %.100s: no home directory %.200s\0" as *const u8
                as *const libc::c_char,
            (*pw).pw_name,
            (*pw).pw_dir,
        );
        auth_debug_add(
            b"Rhosts authentication refused for %.100s: no home directory %.200s\0" as *const u8
                as *const libc::c_char,
            (*pw).pw_name,
            (*pw).pw_dir,
        );
        return 0 as libc::c_int;
    }
    if options.strict_modes != 0
        && (st.st_uid != 0 as libc::c_int as libc::c_uint && st.st_uid != (*pw).pw_uid
            || st.st_mode & 0o22 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint)
    {
        sshlog(
            b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<
                &[u8; 13],
                &[libc::c_char; 13],
            >(b"auth_rhosts2\0"))
                .as_ptr(),
            272 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_INFO,
            0 as *const libc::c_char,
            b"Rhosts authentication refused for %.100s: bad ownership or modes for home directory.\0"
                as *const u8 as *const libc::c_char,
            (*pw).pw_name,
        );
        auth_debug_add(
            b"Rhosts authentication refused for %.100s: bad ownership or modes for home directory.\0"
                as *const u8 as *const libc::c_char,
            (*pw).pw_name,
        );
        return 0 as libc::c_int;
    }
    temporarily_use_uid(pw);
    rhosts_file_index = 0 as libc::c_int as u_int;
    while !(rhosts_files[rhosts_file_index as usize]).is_null() {
        xasprintf(
            &mut path as *mut *mut libc::c_char,
            b"%s/%s\0" as *const u8 as *const libc::c_char,
            (*pw).pw_dir,
            rhosts_files[rhosts_file_index as usize],
        );
        if stat(path, &mut st) == -(1 as libc::c_int) {
            sshlog(
                b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"auth_rhosts2\0"))
                    .as_ptr(),
                287 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"stat %s: %s\0" as *const u8 as *const libc::c_char,
                path,
                strerror(*__errno_location()),
            );
            free(path as *mut libc::c_void);
        } else if options.strict_modes != 0
            && (st.st_uid != 0 as libc::c_int as libc::c_uint && st.st_uid != (*pw).pw_uid
                || st.st_mode & 0o22 as libc::c_int as libc::c_uint
                    != 0 as libc::c_int as libc::c_uint)
        {
            sshlog(
                b"auth-rhosts.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"auth_rhosts2\0"))
                    .as_ptr(),
                302 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_INFO,
                0 as *const libc::c_char,
                b"Rhosts authentication refused for %.100s: bad modes for %.200s\0" as *const u8
                    as *const libc::c_char,
                (*pw).pw_name,
                path,
            );
            auth_debug_add(
                b"Bad file modes for %.200s\0" as *const u8 as *const libc::c_char,
                path,
            );
            free(path as *mut libc::c_void);
        } else if options.ignore_rhosts == 1 as libc::c_int
            || options.ignore_rhosts == 2 as libc::c_int
                && strcmp(
                    rhosts_files[rhosts_file_index as usize],
                    b".shosts\0" as *const u8 as *const libc::c_char,
                ) != 0 as libc::c_int
        {
            auth_debug_add(
                b"Server has been configured to ignore %.100s.\0" as *const u8
                    as *const libc::c_char,
                rhosts_files[rhosts_file_index as usize],
            );
            free(path as *mut libc::c_void);
        } else {
            if check_rhosts_file(path, hostname, ipaddr, client_user, (*pw).pw_name) != 0 {
                auth_debug_add(
                    b"Accepted by %.100s.\0" as *const u8 as *const libc::c_char,
                    rhosts_files[rhosts_file_index as usize],
                );
                restore_uid();
                auth_debug_add(
                    b"Accepted host %s ip %s client_user %s server_user %s\0" as *const u8
                        as *const libc::c_char,
                    hostname,
                    ipaddr,
                    client_user,
                    (*pw).pw_name,
                );
                free(path as *mut libc::c_void);
                return 1 as libc::c_int;
            }
            free(path as *mut libc::c_void);
        }
        rhosts_file_index = rhosts_file_index.wrapping_add(1);
        rhosts_file_index;
    }
    restore_uid();
    return 0 as libc::c_int;
}
