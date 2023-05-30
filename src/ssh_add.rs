use crate::log::log_init;
use crate::sshkey::sshkey_sig_details;
use ::libc;
use libc::close;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;

    static mut BSDoptarg: *mut libc::c_char;
    static mut BSDoptind: libc::c_int;

    static mut stdin: *mut libc::FILE;
    static mut stdout: *mut libc::FILE;
    static mut stderr: *mut libc::FILE;
    fn setvbuf(
        __stream: *mut libc::FILE,
        __buf: *mut libc::c_char,
        __modes: libc::c_int,
        __n: size_t,
    ) -> libc::c_int;

    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;

    fn __getdelim(
        __lineptr: *mut *mut libc::c_char,
        __n: *mut size_t,
        __delimiter: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> __ssize_t;

    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;

    fn arc4random_buf(_: *mut libc::c_void, _: size_t);

    fn freezero(_: *mut libc::c_void, _: size_t);
    fn seed_rng();

    fn getenv(__name: *const libc::c_char) -> *mut libc::c_char;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;

    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;

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
    fn sshkey_new(_: libc::c_int) -> *mut crate::sshkey::sshkey;

    fn sshkey_write(_: *const crate::sshkey::sshkey, _: *mut libc::FILE) -> libc::c_int;
    fn sshkey_read(_: *mut crate::sshkey::sshkey, _: *mut *mut libc::c_char) -> libc::c_int;
    fn sshkey_size(_: *const crate::sshkey::sshkey) -> u_int;

    fn sshkey_is_sk(_: *const crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_type_plain(_: libc::c_int) -> libc::c_int;
    fn sshkey_to_certified(_: *mut crate::sshkey::sshkey) -> libc::c_int;
    fn sshkey_cert_copy(
        _: *const crate::sshkey::sshkey,
        _: *mut crate::sshkey::sshkey,
    ) -> libc::c_int;
    fn sshkey_verify(
        _: *const crate::sshkey::sshkey,
        _: *const u_char,
        _: size_t,
        _: *const u_char,
        _: size_t,
        _: *const libc::c_char,
        _: u_int,
        _: *mut *mut sshkey_sig_details,
    ) -> libc::c_int;
    fn sshkey_parse_private_fileblob(
        buffer: *mut crate::sshbuf::sshbuf,
        passphrase: *const libc::c_char,
        keyp: *mut *mut crate::sshkey::sshkey,
        commentp: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sshkey_set_filename(_: *mut crate::sshkey::sshkey, _: *const libc::c_char) -> libc::c_int;
    fn sshkey_signatures_left(_: *const crate::sshkey::sshkey) -> u_int32_t;

    fn sshbuf_load_fd(_: libc::c_int, _: *mut *mut crate::sshbuf::sshbuf) -> libc::c_int;
    fn ssh_get_authentication_socket(fdp: *mut libc::c_int) -> libc::c_int;
    fn ssh_close_authentication_socket(sock: libc::c_int);
    fn ssh_lock_agent(
        sock: libc::c_int,
        lock: libc::c_int,
        password: *const libc::c_char,
    ) -> libc::c_int;
    fn ssh_fetch_identitylist(sock: libc::c_int, idlp: *mut *mut ssh_identitylist) -> libc::c_int;
    fn ssh_free_identitylist(idl: *mut ssh_identitylist);
    fn ssh_add_identity_constrained(
        sock: libc::c_int,
        key: *mut crate::sshkey::sshkey,
        comment: *const libc::c_char,
        life: u_int,
        confirm_0: u_int,
        maxsign_0: u_int,
        provider: *const libc::c_char,
        dest_constraints: *mut *mut dest_constraint,
        ndest_constraints: size_t,
    ) -> libc::c_int;
    fn ssh_remove_identity(sock: libc::c_int, key: *const crate::sshkey::sshkey) -> libc::c_int;
    fn ssh_update_card(
        sock: libc::c_int,
        add: libc::c_int,
        reader_id: *const libc::c_char,
        pin: *const libc::c_char,
        life: u_int,
        confirm_0: u_int,
        dest_constraints: *mut *mut dest_constraint,
        ndest_constraints: size_t,
    ) -> libc::c_int;
    fn ssh_remove_all_identities(sock: libc::c_int, version: libc::c_int) -> libc::c_int;
    fn ssh_agent_sign(
        sock: libc::c_int,
        key: *const crate::sshkey::sshkey,
        sigp: *mut *mut u_char,
        lenp: *mut size_t,
        data: *const u_char,
        datalen: size_t,
        alg: *const libc::c_char,
        compat: u_int,
    ) -> libc::c_int;
    fn sshkey_load_public(
        _: *const libc::c_char,
        _: *mut *mut crate::sshkey::sshkey,
        _: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sshkey_perm_ok(_: libc::c_int, _: *const libc::c_char) -> libc::c_int;
    fn cleanhostname(_: *mut libc::c_char) -> *mut libc::c_char;
    fn convtime(_: *const libc::c_char) -> libc::c_int;
    fn tilde_expand_filename(_: *const libc::c_char, _: uid_t) -> *mut libc::c_char;

    fn read_passphrase(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn ssh_digest_alg_by_name(name: *const libc::c_char) -> libc::c_int;
    fn sshsk_load_resident(
        provider_path: *const libc::c_char,
        device: *const libc::c_char,
        pin: *const libc::c_char,
        flags: u_int,
        srksp: *mut *mut *mut sshsk_resident_key,
        nsrksp: *mut size_t,
    ) -> libc::c_int;
    fn sshsk_free_resident_keys(srks: *mut *mut sshsk_resident_key, nsrks: size_t);
    fn init_hostkeys() -> *mut hostkeys;
    fn load_hostkeys(_: *mut hostkeys, _: *const libc::c_char, _: *const libc::c_char, _: u_int);
    fn free_hostkeys(_: *mut hostkeys);
    static mut __progname: *mut libc::c_char;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
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
pub type __ssize_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type uid_t = __uid_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;

pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;

pub type _IO_lock_t = ();

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
pub struct ssh_identitylist {
    pub nkeys: size_t,
    pub keys: *mut *mut crate::sshkey::sshkey,
    pub comments: *mut *mut libc::c_char,
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dest_constraint {
    pub from: dest_constraint_hop,
    pub to: dest_constraint_hop,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sshsk_resident_key {
    pub key: *mut crate::sshkey::sshkey,
    pub user_id: *mut uint8_t,
    pub user_id_len: size_t,
}
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
#[inline]
unsafe extern "C" fn getline(
    mut __lineptr: *mut *mut libc::c_char,
    mut __n: *mut size_t,
    mut __stream: *mut libc::FILE,
) -> __ssize_t {
    return __getdelim(__lineptr, __n, '\n' as i32, __stream);
}
static mut default_files: [*mut libc::c_char; 8] = [
    b".ssh/id_rsa\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    b".ssh/id_ecdsa\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    b".ssh/id_ecdsa_sk\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    b".ssh/id_ed25519\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    b".ssh/id_ed25519_sk\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    b".ssh/id_xmss\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    b".ssh/id_dsa\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    0 as *const libc::c_char as *mut libc::c_char,
];
static mut fingerprint_hash: libc::c_int = 2 as libc::c_int;
static mut lifetime: libc::c_int = 0 as libc::c_int;
static mut confirm: libc::c_int = 0 as libc::c_int;
static mut maxsign: u_int = 0 as libc::c_int as u_int;
static mut minleft: u_int = 0 as libc::c_int as u_int;
static mut pass: *mut libc::c_char = 0 as *const libc::c_char as *mut libc::c_char;
unsafe extern "C" fn clear_pass() {
    if !pass.is_null() {
        freezero(pass as *mut libc::c_void, strlen(pass));
        pass = 0 as *mut libc::c_char;
    }
}
unsafe extern "C" fn delete_one(
    mut agent_fd: libc::c_int,
    mut key: *const crate::sshkey::sshkey,
    mut comment: *const libc::c_char,
    mut path: *const libc::c_char,
    mut qflag: libc::c_int,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = ssh_remove_identity(agent_fd, key);
    if r != 0 as libc::c_int {
        libc::fprintf(
            stderr,
            b"Could not remove identity \"%s\": %s\n\0" as *const u8 as *const libc::c_char,
            path,
            ssh_err(r),
        );
        return r;
    }
    if qflag == 0 {
        libc::fprintf(
            stderr,
            b"Identity removed: %s %s (%s)\n\0" as *const u8 as *const libc::c_char,
            path,
            crate::sshkey::sshkey_type(key),
            if !comment.is_null() {
                comment
            } else {
                b"no comment\0" as *const u8 as *const libc::c_char
            },
        );
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn delete_stdin(
    mut agent_fd: libc::c_int,
    mut qflag: libc::c_int,
) -> libc::c_int {
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut lnum: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    while getline(&mut line, &mut linesize, stdin) != -(1 as libc::c_int) as libc::c_long {
        lnum += 1;
        lnum;
        crate::sshkey::sshkey_free(key);
        key = 0 as *mut crate::sshkey::sshkey;
        *line.offset(strcspn(line, b"\n\0" as *const u8 as *const libc::c_char) as isize) =
            '\0' as i32 as libc::c_char;
        cp = line.offset(strspn(line, b" \t\0" as *const u8 as *const libc::c_char) as isize);
        if *cp as libc::c_int == '#' as i32 || *cp as libc::c_int == '\0' as i32 {
            continue;
        }
        key = sshkey_new(KEY_UNSPEC as libc::c_int);
        if key.is_null() {
            sshfatal(
                b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"delete_stdin\0"))
                    .as_ptr(),
                150 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"sshkey_new\0" as *const u8 as *const libc::c_char,
            );
        }
        r = sshkey_read(key, &mut cp);
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"delete_stdin\0"))
                    .as_ptr(),
                152 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"(stdin):%d: invalid key\0" as *const u8 as *const libc::c_char,
                lnum,
            );
        } else if delete_one(
            agent_fd,
            key,
            cp,
            b"(stdin)\0" as *const u8 as *const libc::c_char,
            qflag,
        ) == 0 as libc::c_int
        {
            ret = 0 as libc::c_int;
        }
    }
    crate::sshkey::sshkey_free(key);
    libc::free(line as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn delete_file(
    mut agent_fd: libc::c_int,
    mut filename: *const libc::c_char,
    mut key_only: libc::c_int,
    mut qflag: libc::c_int,
) -> libc::c_int {
    let mut public: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut cert: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut certpath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if libc::strcmp(filename, b"-\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        return delete_stdin(agent_fd, qflag);
    }
    r = sshkey_load_public(filename, &mut public, &mut comment);
    if r != 0 as libc::c_int {
        printf(
            b"Bad key file %s: %s\n\0" as *const u8 as *const libc::c_char,
            filename,
            ssh_err(r),
        );
        return -(1 as libc::c_int);
    }
    if delete_one(agent_fd, public, comment, filename, qflag) == 0 as libc::c_int {
        ret = 0 as libc::c_int;
    }
    if !(key_only != 0) {
        libc::free(comment as *mut libc::c_void);
        comment = 0 as *mut libc::c_char;
        crate::xmalloc::xasprintf(
            &mut certpath as *mut *mut libc::c_char,
            b"%s-cert.pub\0" as *const u8 as *const libc::c_char,
            filename,
        );
        r = sshkey_load_public(certpath, &mut cert, &mut comment);
        if r != 0 as libc::c_int {
            if r != -(24 as libc::c_int) || *libc::__errno_location() != 2 as libc::c_int {
                crate::log::sshlog(
                    b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"delete_file\0"))
                        .as_ptr(),
                    189 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    ssh_err(r),
                    b"Failed to load certificate \"%s\"\0" as *const u8 as *const libc::c_char,
                    certpath,
                );
            }
        } else {
            if crate::sshkey::sshkey_equal_public(cert, public) == 0 {
                sshfatal(
                    b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"delete_file\0"))
                        .as_ptr(),
                    195 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Certificate %s does not match private key %s\0" as *const u8
                        as *const libc::c_char,
                    certpath,
                    filename,
                );
            }
            if delete_one(agent_fd, cert, comment, certpath, qflag) == 0 as libc::c_int {
                ret = 0 as libc::c_int;
            }
        }
    }
    crate::sshkey::sshkey_free(cert);
    crate::sshkey::sshkey_free(public);
    libc::free(certpath as *mut libc::c_void);
    libc::free(comment as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn delete_all(mut agent_fd: libc::c_int, mut qflag: libc::c_int) -> libc::c_int {
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if ssh_remove_all_identities(agent_fd, 2 as libc::c_int) == 0 as libc::c_int {
        ret = 0 as libc::c_int;
    }
    ssh_remove_all_identities(agent_fd, 1 as libc::c_int);
    if ret != 0 as libc::c_int {
        libc::fprintf(
            stderr,
            b"Failed to remove all identities.\n\0" as *const u8 as *const libc::c_char,
        );
    } else if qflag == 0 {
        libc::fprintf(
            stderr,
            b"All identities removed.\n\0" as *const u8 as *const libc::c_char,
        );
    }
    return ret;
}
unsafe extern "C" fn add_file(
    mut agent_fd: libc::c_int,
    mut filename: *const libc::c_char,
    mut key_only: libc::c_int,
    mut qflag: libc::c_int,
    mut skprovider: *const libc::c_char,
    mut dest_constraints: *mut *mut dest_constraint,
    mut ndest_constraints: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut private: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut cert: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut comment: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut msg: [libc::c_char; 1024] = [0; 1024];
    let mut certpath: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut i: size_t = 0;
    let mut left: u_int32_t = 0;
    let mut keyblob: *mut crate::sshbuf::sshbuf = 0 as *mut crate::sshbuf::sshbuf;
    let mut idlist: *mut ssh_identitylist = 0 as *mut ssh_identitylist;
    if libc::strcmp(filename, b"-\0" as *const u8 as *const libc::c_char) == 0 as libc::c_int {
        fd = 0 as libc::c_int;
        filename = b"(stdin)\0" as *const u8 as *const libc::c_char;
    } else {
        fd = libc::open(filename, 0 as libc::c_int);
        if fd == -(1 as libc::c_int) {
            libc::perror(filename);
            return -(1 as libc::c_int);
        }
    }
    if fd != 0 as libc::c_int {
        if sshkey_perm_ok(fd, filename) != 0 as libc::c_int {
            close(fd);
            return -(1 as libc::c_int);
        }
    }
    r = sshbuf_load_fd(fd, &mut keyblob);
    if r != 0 as libc::c_int {
        libc::fprintf(
            stderr,
            b"Error loading key \"%s\": %s\n\0" as *const u8 as *const libc::c_char,
            filename,
            ssh_err(r),
        );
        crate::sshbuf::sshbuf_free(keyblob);
        close(fd);
        return -(1 as libc::c_int);
    }
    close(fd);
    r = sshkey_parse_private_fileblob(
        keyblob,
        b"\0" as *const u8 as *const libc::c_char,
        &mut private,
        &mut comment,
    );
    if r != 0 as libc::c_int && r != -(43 as libc::c_int) {
        libc::fprintf(
            stderr,
            b"Error loading key \"%s\": %s\n\0" as *const u8 as *const libc::c_char,
            filename,
            ssh_err(r),
        );
    } else {
        if private.is_null() && !pass.is_null() {
            r = sshkey_parse_private_fileblob(keyblob, pass, &mut private, &mut comment);
            if r != 0 as libc::c_int && r != -(43 as libc::c_int) {
                libc::fprintf(
                    stderr,
                    b"Error loading key \"%s\": %s\n\0" as *const u8 as *const libc::c_char,
                    filename,
                    ssh_err(r),
                );
                current_block = 10441068446736761227;
            } else {
                current_block = 14401909646449704462;
            }
        } else {
            current_block = 14401909646449704462;
        }
        match current_block {
            10441068446736761227 => {}
            _ => {
                if private.is_null() {
                    clear_pass();
                    libc::snprintf(
                        msg.as_mut_ptr(),
                        ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
                        b"Enter passphrase for %s%s: \0" as *const u8 as *const libc::c_char,
                        filename,
                        if confirm != 0 {
                            b" (will confirm each use)\0" as *const u8 as *const libc::c_char
                        } else {
                            b"\0" as *const u8 as *const libc::c_char
                        },
                    );
                    loop {
                        pass = read_passphrase(msg.as_mut_ptr(), 0x2 as libc::c_int);
                        if libc::strcmp(pass, b"\0" as *const u8 as *const libc::c_char)
                            == 0 as libc::c_int
                        {
                            current_block = 10441068446736761227;
                            break;
                        }
                        r = sshkey_parse_private_fileblob(
                            keyblob,
                            pass,
                            &mut private,
                            &mut comment,
                        );
                        if r == 0 as libc::c_int {
                            current_block = 7245201122033322888;
                            break;
                        }
                        if r != -(43 as libc::c_int) {
                            libc::fprintf(
                                stderr,
                                b"Error loading key \"%s\": %s\n\0" as *const u8
                                    as *const libc::c_char,
                                filename,
                                ssh_err(r),
                            );
                            current_block = 10441068446736761227;
                            break;
                        } else {
                            clear_pass();
                            libc::snprintf(
                                msg.as_mut_ptr(),
                                ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
                                b"Bad passphrase, try again for %s%s: \0" as *const u8
                                    as *const libc::c_char,
                                filename,
                                if confirm != 0 {
                                    b" (will confirm each use)\0" as *const u8
                                        as *const libc::c_char
                                } else {
                                    b"\0" as *const u8 as *const libc::c_char
                                },
                            );
                        }
                    }
                } else {
                    current_block = 7245201122033322888;
                }
                match current_block {
                    10441068446736761227 => {}
                    _ => {
                        if comment.is_null() || *comment as libc::c_int == '\0' as i32 {
                            comment = crate::xmalloc::xstrdup(filename);
                        }
                        crate::sshbuf::sshbuf_free(keyblob);
                        r = sshkey_set_filename(private, filename);
                        if r != 0 as libc::c_int {
                            libc::fprintf(
                                stderr,
                                b"Could not add filename to private key: %s (%s)\n\0" as *const u8
                                    as *const libc::c_char,
                                filename,
                                comment,
                            );
                        } else {
                            if maxsign != 0 && minleft != 0 && {
                                r = ssh_fetch_identitylist(agent_fd, &mut idlist);
                                r == 0 as libc::c_int
                            } {
                                i = 0 as libc::c_int as size_t;
                                loop {
                                    if !(i < (*idlist).nkeys) {
                                        current_block = 10095721787123848864;
                                        break;
                                    }
                                    if crate::sshkey::sshkey_equal_public(
                                        *((*idlist).keys).offset(i as isize),
                                        private,
                                    ) == 0
                                    {
                                        i = i.wrapping_add(1);
                                        i;
                                    } else {
                                        left = sshkey_signatures_left(
                                            *((*idlist).keys).offset(i as isize),
                                        );
                                        if left < minleft {
                                            libc::fprintf(
                                                stderr,
                                                b"Only %d signatures left.\n\0" as *const u8
                                                    as *const libc::c_char,
                                                left,
                                            );
                                            current_block = 10095721787123848864;
                                            break;
                                        } else {
                                            libc::fprintf(
                                                stderr,
                                                b"Skipping update: \0" as *const u8
                                                    as *const libc::c_char,
                                            );
                                            if left == minleft {
                                                libc::fprintf(
                                                    stderr,
                                                    b"required signatures left (%d).\n\0"
                                                        as *const u8
                                                        as *const libc::c_char,
                                                    left,
                                                );
                                            } else {
                                                libc::fprintf(
                                                    stderr,
                                                    b"more signatures left (%d) than required (%d).\n\0"
                                                        as *const u8 as *const libc::c_char,
                                                    left,
                                                    minleft,
                                                );
                                            }
                                            ssh_free_identitylist(idlist);
                                            current_block = 12847670832947016629;
                                            break;
                                        }
                                    }
                                }
                                match current_block {
                                    12847670832947016629 => {}
                                    _ => {
                                        ssh_free_identitylist(idlist);
                                        current_block = 13826291924415791078;
                                    }
                                }
                            } else {
                                current_block = 13826291924415791078;
                            }
                            match current_block {
                                12847670832947016629 => {}
                                _ => {
                                    if sshkey_is_sk(private) != 0 {
                                        if skprovider.is_null() {
                                            libc::fprintf(
                                                stderr,
                                                b"Cannot load FIDO key %s without provider\n\0"
                                                    as *const u8
                                                    as *const libc::c_char,
                                                filename,
                                            );
                                            current_block = 12847670832947016629;
                                        } else {
                                            current_block = 5159818223158340697;
                                        }
                                    } else {
                                        skprovider = 0 as *const libc::c_char;
                                        current_block = 5159818223158340697;
                                    }
                                    match current_block {
                                        12847670832947016629 => {}
                                        _ => {
                                            r = ssh_add_identity_constrained(
                                                agent_fd,
                                                private,
                                                comment,
                                                lifetime as u_int,
                                                confirm as u_int,
                                                maxsign,
                                                skprovider,
                                                dest_constraints,
                                                ndest_constraints,
                                            );
                                            if r == 0 as libc::c_int {
                                                ret = 0 as libc::c_int;
                                                if qflag == 0 {
                                                    libc::fprintf(
                                                        stderr,
                                                        b"Identity added: %s (%s)\n\0" as *const u8
                                                            as *const libc::c_char,
                                                        filename,
                                                        comment,
                                                    );
                                                    if lifetime != 0 as libc::c_int {
                                                        libc::fprintf(
                                                            stderr,
                                                            b"Lifetime set to %d seconds\n\0"
                                                                as *const u8
                                                                as *const libc::c_char,
                                                            lifetime,
                                                        );
                                                    }
                                                    if confirm != 0 as libc::c_int {
                                                        libc::fprintf(
                                                            stderr,
                                                            b"The user must confirm each use of the key\n\0"
                                                                as *const u8 as *const libc::c_char,
                                                        );
                                                    }
                                                }
                                            } else {
                                                libc::fprintf(
                                                    stderr,
                                                    b"Could not add identity \"%s\": %s\n\0"
                                                        as *const u8
                                                        as *const libc::c_char,
                                                    filename,
                                                    ssh_err(r),
                                                );
                                            }
                                            if !(key_only != 0) {
                                                crate::xmalloc::xasprintf(
                                                    &mut certpath as *mut *mut libc::c_char,
                                                    b"%s-cert.pub\0" as *const u8
                                                        as *const libc::c_char,
                                                    filename,
                                                );
                                                r = sshkey_load_public(
                                                    certpath,
                                                    &mut cert,
                                                    0 as *mut *mut libc::c_char,
                                                );
                                                if r != 0 as libc::c_int {
                                                    if r != -(24 as libc::c_int)
                                                        || *libc::__errno_location()
                                                            != 2 as libc::c_int
                                                    {
                                                        crate::log::sshlog(
                                                            b"ssh-add.c\0" as *const u8
                                                                as *const libc::c_char,
                                                            (*::core::mem::transmute::<
                                                                &[u8; 9],
                                                                &[libc::c_char; 9],
                                                            >(
                                                                b"add_file\0"
                                                            ))
                                                            .as_ptr(),
                                                            393 as libc::c_int,
                                                            0 as libc::c_int,
                                                            SYSLOG_LEVEL_ERROR,
                                                            ssh_err(r),
                                                            b"Failed to load certificate \"%s\"\0"
                                                                as *const u8
                                                                as *const libc::c_char,
                                                            certpath,
                                                        );
                                                    }
                                                } else if crate::sshkey::sshkey_equal_public(
                                                    cert, private,
                                                ) == 0
                                                {
                                                    crate::log::sshlog(
                                                        b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                                                        (*::core::mem::transmute::<
                                                            &[u8; 9],
                                                            &[libc::c_char; 9],
                                                        >(b"add_file\0"))
                                                            .as_ptr(),
                                                        399 as libc::c_int,
                                                        0 as libc::c_int,
                                                        SYSLOG_LEVEL_ERROR,
                                                        0 as *const libc::c_char,
                                                        b"Certificate %s does not match private key %s\0"
                                                            as *const u8 as *const libc::c_char,
                                                        certpath,
                                                        filename,
                                                    );
                                                    crate::sshkey::sshkey_free(cert);
                                                } else {
                                                    r = sshkey_to_certified(private);
                                                    if r != 0 as libc::c_int {
                                                        crate::log::sshlog(
                                                            b"ssh-add.c\0" as *const u8
                                                                as *const libc::c_char,
                                                            (*::core::mem::transmute::<
                                                                &[u8; 9],
                                                                &[libc::c_char; 9],
                                                            >(
                                                                b"add_file\0"
                                                            ))
                                                            .as_ptr(),
                                                            406 as libc::c_int,
                                                            1 as libc::c_int,
                                                            SYSLOG_LEVEL_ERROR,
                                                            ssh_err(r),
                                                            b"sshkey_to_certified\0" as *const u8
                                                                as *const libc::c_char,
                                                        );
                                                        crate::sshkey::sshkey_free(cert);
                                                    } else {
                                                        r = sshkey_cert_copy(cert, private);
                                                        if r != 0 as libc::c_int {
                                                            crate::log::sshlog(
                                                                b"ssh-add.c\0" as *const u8
                                                                    as *const libc::c_char,
                                                                (*::core::mem::transmute::<
                                                                    &[u8; 9],
                                                                    &[libc::c_char; 9],
                                                                >(
                                                                    b"add_file\0"
                                                                ))
                                                                .as_ptr(),
                                                                411 as libc::c_int,
                                                                1 as libc::c_int,
                                                                SYSLOG_LEVEL_ERROR,
                                                                ssh_err(r),
                                                                b"sshkey_cert_copy\0" as *const u8
                                                                    as *const libc::c_char,
                                                            );
                                                            crate::sshkey::sshkey_free(cert);
                                                        } else {
                                                            crate::sshkey::sshkey_free(cert);
                                                            r = ssh_add_identity_constrained(
                                                                agent_fd,
                                                                private,
                                                                comment,
                                                                lifetime as u_int,
                                                                confirm as u_int,
                                                                maxsign,
                                                                skprovider,
                                                                dest_constraints,
                                                                ndest_constraints,
                                                            );
                                                            if r != 0 as libc::c_int {
                                                                crate::log::sshlog(
                                                                    b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                                                                    (*::core::mem::transmute::<
                                                                        &[u8; 9],
                                                                        &[libc::c_char; 9],
                                                                    >(b"add_file\0"))
                                                                        .as_ptr(),
                                                                    421 as libc::c_int,
                                                                    0 as libc::c_int,
                                                                    SYSLOG_LEVEL_ERROR,
                                                                    ssh_err(r),
                                                                    b"Certificate %s (%s) add failed\0" as *const u8
                                                                        as *const libc::c_char,
                                                                    certpath,
                                                                    (*(*private).cert).key_id,
                                                                );
                                                            } else if qflag == 0 {
                                                                libc::fprintf(
                                                                    stderr,
                                                                    b"Certificate added: %s (%s)\n\0" as *const u8
                                                                        as *const libc::c_char,
                                                                    certpath,
                                                                    (*(*private).cert).key_id,
                                                                );
                                                                if lifetime != 0 as libc::c_int {
                                                                    libc::fprintf(
                                                                        stderr,
                                                                        b"Lifetime set to %d seconds\n\0" as *const u8
                                                                            as *const libc::c_char,
                                                                        lifetime,
                                                                    );
                                                                }
                                                                if confirm != 0 as libc::c_int {
                                                                    libc::fprintf(
                                                                        stderr,
                                                                        b"The user must confirm each use of the key\n\0"
                                                                            as *const u8 as *const libc::c_char,
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
                        }
                        libc::free(certpath as *mut libc::c_void);
                        libc::free(comment as *mut libc::c_void);
                        crate::sshkey::sshkey_free(private);
                        return ret;
                    }
                }
            }
        }
    }
    clear_pass();
    crate::sshbuf::sshbuf_free(keyblob);
    return -(1 as libc::c_int);
}
unsafe extern "C" fn update_card(
    mut agent_fd: libc::c_int,
    mut add: libc::c_int,
    mut id: *const libc::c_char,
    mut qflag: libc::c_int,
    mut dest_constraints: *mut *mut dest_constraint,
    mut ndest_constraints: size_t,
) -> libc::c_int {
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    if add != 0 {
        pin = read_passphrase(
            b"Enter passphrase for PKCS#11: \0" as *const u8 as *const libc::c_char,
            0x2 as libc::c_int,
        );
        if pin.is_null() {
            return -(1 as libc::c_int);
        }
    }
    r = ssh_update_card(
        agent_fd,
        add,
        id,
        if pin.is_null() {
            b"\0" as *const u8 as *const libc::c_char
        } else {
            pin as *const libc::c_char
        },
        lifetime as u_int,
        confirm as u_int,
        dest_constraints,
        ndest_constraints,
    );
    if r == 0 as libc::c_int {
        ret = 0 as libc::c_int;
        if qflag == 0 {
            libc::fprintf(
                stderr,
                b"Card %s: %s\n\0" as *const u8 as *const libc::c_char,
                if add != 0 {
                    b"added\0" as *const u8 as *const libc::c_char
                } else {
                    b"removed\0" as *const u8 as *const libc::c_char
                },
                id,
            );
        }
    } else {
        libc::fprintf(
            stderr,
            b"Could not %s card \"%s\": %s\n\0" as *const u8 as *const libc::c_char,
            if add != 0 {
                b"add\0" as *const u8 as *const libc::c_char
            } else {
                b"remove\0" as *const u8 as *const libc::c_char
            },
            id,
            ssh_err(r),
        );
        ret = -(1 as libc::c_int);
    }
    libc::free(pin as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn test_key(
    mut agent_fd: libc::c_int,
    mut filename: *const libc::c_char,
) -> libc::c_int {
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut sig: *mut u_char = 0 as *mut u_char;
    let mut alg: *const libc::c_char = 0 as *const libc::c_char;
    let mut slen: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut data: [libc::c_char; 1024] = [0; 1024];
    r = sshkey_load_public(filename, &mut key, 0 as *mut *mut libc::c_char);
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-add.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"test_key\0")).as_ptr(),
            486 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"Couldn't read public key %s\0" as *const u8 as *const libc::c_char,
            filename,
        );
        return -(1 as libc::c_int);
    }
    if sshkey_type_plain((*key).type_0) == KEY_RSA as libc::c_int {
        alg = b"rsa-sha2-256\0" as *const u8 as *const libc::c_char;
    }
    arc4random_buf(
        data.as_mut_ptr() as *mut libc::c_void,
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
    );
    r = ssh_agent_sign(
        agent_fd,
        key,
        &mut sig,
        &mut slen,
        data.as_mut_ptr() as *const u_char,
        ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
        alg,
        0 as libc::c_int as u_int,
    );
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-add.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"test_key\0")).as_ptr(),
            494 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"Agent signature failed for %s\0" as *const u8 as *const libc::c_char,
            filename,
        );
    } else {
        r = sshkey_verify(
            key,
            sig,
            slen,
            data.as_mut_ptr() as *const u_char,
            ::core::mem::size_of::<[libc::c_char; 1024]>() as libc::c_ulong,
            alg,
            0 as libc::c_int as u_int,
            0 as *mut *mut sshkey_sig_details,
        );
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"test_key\0")).as_ptr(),
                499 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"Signature verification failed for %s\0" as *const u8 as *const libc::c_char,
                filename,
            );
        } else {
            ret = 0 as libc::c_int;
        }
    }
    libc::free(sig as *mut libc::c_void);
    crate::sshkey::sshkey_free(key);
    return ret;
}
unsafe extern "C" fn list_identities(
    mut agent_fd: libc::c_int,
    mut do_fp: libc::c_int,
) -> libc::c_int {
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut idlist: *mut ssh_identitylist = 0 as *mut ssh_identitylist;
    let mut left: u_int32_t = 0;
    let mut i: size_t = 0;
    r = ssh_fetch_identitylist(agent_fd, &mut idlist);
    if r != 0 as libc::c_int {
        if r != -(48 as libc::c_int) {
            libc::fprintf(
                stderr,
                b"error fetching identities: %s\n\0" as *const u8 as *const libc::c_char,
                ssh_err(r),
            );
        } else {
            printf(b"The agent has no identities.\n\0" as *const u8 as *const libc::c_char);
        }
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int as size_t;
    while i < (*idlist).nkeys {
        if do_fp != 0 {
            fp = crate::sshkey::sshkey_fingerprint(
                *((*idlist).keys).offset(i as isize),
                fingerprint_hash,
                SSH_FP_DEFAULT,
            );
            printf(
                b"%u %s %s (%s)\n\0" as *const u8 as *const libc::c_char,
                sshkey_size(*((*idlist).keys).offset(i as isize)),
                if fp.is_null() {
                    b"(null)\0" as *const u8 as *const libc::c_char
                } else {
                    fp as *const libc::c_char
                },
                *((*idlist).comments).offset(i as isize),
                crate::sshkey::sshkey_type(*((*idlist).keys).offset(i as isize)),
            );
            libc::free(fp as *mut libc::c_void);
        } else {
            r = sshkey_write(*((*idlist).keys).offset(i as isize), stdout);
            if r != 0 as libc::c_int {
                libc::fprintf(
                    stderr,
                    b"sshkey_write: %s\n\0" as *const u8 as *const libc::c_char,
                    ssh_err(r),
                );
            } else {
                libc::fprintf(
                    stdout,
                    b" %s\0" as *const u8 as *const libc::c_char,
                    *((*idlist).comments).offset(i as isize),
                );
                left = sshkey_signatures_left(*((*idlist).keys).offset(i as isize));
                if left > 0 as libc::c_int as libc::c_uint {
                    libc::fprintf(
                        stdout,
                        b" [signatures left %d]\0" as *const u8 as *const libc::c_char,
                        left,
                    );
                }
                libc::fprintf(stdout, b"\n\0" as *const u8 as *const libc::c_char);
            }
        }
        i = i.wrapping_add(1);
        i;
    }
    ssh_free_identitylist(idlist);
    return 0 as libc::c_int;
}
unsafe extern "C" fn lock_agent(mut agent_fd: libc::c_int, mut lock: libc::c_int) -> libc::c_int {
    let mut prompt: [libc::c_char; 100] = [0; 100];
    let mut p1: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p2: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut passok: libc::c_int = 1 as libc::c_int;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    strlcpy(
        prompt.as_mut_ptr(),
        b"Enter lock password: \0" as *const u8 as *const libc::c_char,
        ::core::mem::size_of::<[libc::c_char; 100]>() as libc::c_ulong,
    );
    p1 = read_passphrase(prompt.as_mut_ptr(), 0x2 as libc::c_int);
    if lock != 0 {
        strlcpy(
            prompt.as_mut_ptr(),
            b"Again: \0" as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<[libc::c_char; 100]>() as libc::c_ulong,
        );
        p2 = read_passphrase(prompt.as_mut_ptr(), 0x2 as libc::c_int);
        if libc::strcmp(p1, p2) != 0 as libc::c_int {
            libc::fprintf(
                stderr,
                b"Passwords do not match.\n\0" as *const u8 as *const libc::c_char,
            );
            passok = 0 as libc::c_int;
        }
        freezero(p2 as *mut libc::c_void, strlen(p2));
    }
    if passok != 0 {
        r = ssh_lock_agent(agent_fd, lock, p1);
        if r == 0 as libc::c_int {
            libc::fprintf(
                stderr,
                b"Agent %slocked.\n\0" as *const u8 as *const libc::c_char,
                if lock != 0 {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    b"un\0" as *const u8 as *const libc::c_char
                },
            );
            ret = 0 as libc::c_int;
        } else {
            libc::fprintf(
                stderr,
                b"Failed to %slock agent: %s\n\0" as *const u8 as *const libc::c_char,
                if lock != 0 {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    b"un\0" as *const u8 as *const libc::c_char
                },
                ssh_err(r),
            );
        }
    }
    freezero(p1 as *mut libc::c_void, strlen(p1));
    return ret;
}
unsafe extern "C" fn load_resident_keys(
    mut agent_fd: libc::c_int,
    mut skprovider: *const libc::c_char,
    mut qflag: libc::c_int,
    mut dest_constraints: *mut *mut dest_constraint,
    mut ndest_constraints: size_t,
) -> libc::c_int {
    let mut srks: *mut *mut sshsk_resident_key = 0 as *mut *mut sshsk_resident_key;
    let mut nsrks: size_t = 0;
    let mut i: size_t = 0;
    let mut key: *mut crate::sshkey::sshkey = 0 as *mut crate::sshkey::sshkey;
    let mut r: libc::c_int = 0;
    let mut ok: libc::c_int = 0 as libc::c_int;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    pass = read_passphrase(
        b"Enter PIN for authenticator: \0" as *const u8 as *const libc::c_char,
        0x2 as libc::c_int,
    );
    r = sshsk_load_resident(
        skprovider,
        0 as *const libc::c_char,
        pass,
        0 as libc::c_int as u_int,
        &mut srks,
        &mut nsrks,
    );
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-add.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"load_resident_keys\0"))
                .as_ptr(),
            596 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            ssh_err(r),
            b"Unable to load resident keys\0" as *const u8 as *const libc::c_char,
        );
        return r;
    }
    i = 0 as libc::c_int as size_t;
    while i < nsrks {
        key = (**srks.offset(i as isize)).key;
        fp = crate::sshkey::sshkey_fingerprint(key, fingerprint_hash, SSH_FP_DEFAULT);
        if fp.is_null() {
            sshfatal(
                b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"load_resident_keys\0",
                ))
                .as_ptr(),
                603 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"crate::sshkey::sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
            );
        }
        r = ssh_add_identity_constrained(
            agent_fd,
            key,
            b"\0" as *const u8 as *const libc::c_char,
            lifetime as u_int,
            confirm as u_int,
            maxsign,
            skprovider,
            dest_constraints,
            ndest_constraints,
        );
        if r != 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                    b"load_resident_keys\0",
                ))
                .as_ptr(),
                608 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"Unable to add key %s %s\0" as *const u8 as *const libc::c_char,
                crate::sshkey::sshkey_type(key),
                fp,
            );
            libc::free(fp as *mut libc::c_void);
            ok = r;
        } else {
            if ok == 0 as libc::c_int {
                ok = 1 as libc::c_int;
            }
            if qflag == 0 {
                libc::fprintf(
                    stderr,
                    b"Resident identity added: %s %s\n\0" as *const u8 as *const libc::c_char,
                    crate::sshkey::sshkey_type(key),
                    fp,
                );
                if lifetime != 0 as libc::c_int {
                    libc::fprintf(
                        stderr,
                        b"Lifetime set to %d seconds\n\0" as *const u8 as *const libc::c_char,
                        lifetime,
                    );
                }
                if confirm != 0 as libc::c_int {
                    libc::fprintf(
                        stderr,
                        b"The user must confirm each use of the key\n\0" as *const u8
                            as *const libc::c_char,
                    );
                }
            }
            libc::free(fp as *mut libc::c_void);
        }
        i = i.wrapping_add(1);
        i;
    }
    sshsk_free_resident_keys(srks, nsrks);
    if nsrks == 0 as libc::c_int as libc::c_ulong {
        return -(46 as libc::c_int);
    }
    return if ok == 1 as libc::c_int {
        0 as libc::c_int
    } else {
        ok
    };
}
unsafe extern "C" fn do_file(
    mut agent_fd: libc::c_int,
    mut deleting: libc::c_int,
    mut key_only: libc::c_int,
    mut file: *mut libc::c_char,
    mut qflag: libc::c_int,
    mut skprovider: *const libc::c_char,
    mut dest_constraints: *mut *mut dest_constraint,
    mut ndest_constraints: size_t,
) -> libc::c_int {
    if deleting != 0 {
        if delete_file(agent_fd, file, key_only, qflag) == -(1 as libc::c_int) {
            return -(1 as libc::c_int);
        }
    } else if add_file(
        agent_fd,
        file,
        key_only,
        qflag,
        skprovider,
        dest_constraints,
        ndest_constraints,
    ) == -(1 as libc::c_int)
    {
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn stringlist_append(
    mut listp: *mut *mut *mut libc::c_char,
    mut s: *const libc::c_char,
) {
    let mut i: size_t = 0 as libc::c_int as size_t;
    if (*listp).is_null() {
        *listp = crate::xmalloc::xcalloc(
            2 as libc::c_int as size_t,
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        ) as *mut *mut libc::c_char;
    } else {
        i = 0 as libc::c_int as size_t;
        while !(*(*listp).offset(i as isize)).is_null() {
            i = i.wrapping_add(1);
            i;
        }
        *listp = crate::xmalloc::xrecallocarray(
            *listp as *mut libc::c_void,
            i.wrapping_add(1 as libc::c_int as libc::c_ulong),
            i.wrapping_add(2 as libc::c_int as libc::c_ulong),
            ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
        ) as *mut *mut libc::c_char;
    }
    let ref mut fresh0 = *(*listp).offset(i as isize);
    *fresh0 = crate::xmalloc::xstrdup(s);
}
unsafe extern "C" fn parse_dest_constraint_hop(
    mut s: *const libc::c_char,
    mut dch: *mut dest_constraint_hop,
    mut hostkey_files: *mut *mut libc::c_char,
) {
    let mut user: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut host: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut os: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut path: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut i: size_t = 0;
    let mut hostkeys: *mut hostkeys = 0 as *mut hostkeys;
    let mut hke: *const hostkey_entry = 0 as *const hostkey_entry;
    let mut r: libc::c_int = 0;
    let mut want_ca: libc::c_int = 0;
    memset(
        dch as *mut libc::c_void,
        '\0' as i32,
        ::core::mem::size_of::<dest_constraint_hop>() as libc::c_ulong,
    );
    os = crate::xmalloc::xstrdup(s);
    host = libc::strchr(os, '@' as i32);
    if host.is_null() {
        host = os;
    } else {
        let fresh1 = host;
        host = host.offset(1);
        *fresh1 = '\0' as i32 as libc::c_char;
        user = os;
    }
    cleanhostname(host);
    if *host as libc::c_int == '\0' as i32 {
        if user.is_null() {
            sshfatal(
                b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"parse_dest_constraint_hop\0",
                ))
                .as_ptr(),
                690 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Invalid key destination constraint \"%s\": does not specify user or host\0"
                    as *const u8 as *const libc::c_char,
                s,
            );
        }
        (*dch).user = crate::xmalloc::xstrdup(user);
        libc::free(os as *mut libc::c_void);
        return;
    }
    if hostkey_files.is_null() {
        sshfatal(
            b"ssh-add.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"parse_dest_constraint_hop\0",
            ))
            .as_ptr(),
            698 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"no hostkey files\0" as *const u8 as *const libc::c_char,
        );
    }
    hostkeys = init_hostkeys();
    i = 0 as libc::c_int as size_t;
    while !(*hostkey_files.offset(i as isize)).is_null() {
        path = tilde_expand_filename(*hostkey_files.offset(i as isize), libc::getuid());
        crate::log::sshlog(
            b"ssh-add.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"parse_dest_constraint_hop\0",
            ))
            .as_ptr(),
            703 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"looking up host keys for \"%s\" in %s\0" as *const u8 as *const libc::c_char,
            host,
            path,
        );
        load_hostkeys(hostkeys, host, path, 0 as libc::c_int as u_int);
        libc::free(path as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    (*dch).user = if user.is_null() {
        0 as *mut libc::c_char
    } else {
        crate::xmalloc::xstrdup(user)
    };
    (*dch).hostname = crate::xmalloc::xstrdup(host);
    i = 0 as libc::c_int as size_t;
    while i < (*hostkeys).num_entries as libc::c_ulong {
        hke = ((*hostkeys).entries).offset(i as isize);
        want_ca =
            ((*hke).marker as libc::c_uint == MRK_CA as libc::c_int as libc::c_uint) as libc::c_int;
        if !((*hke).marker as libc::c_uint != MRK_NONE as libc::c_int as libc::c_uint
            && want_ca == 0)
        {
            crate::log::sshlog(
                b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"parse_dest_constraint_hop\0",
                ))
                .as_ptr(),
                717 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"%s%s%s: adding %s %skey from %s:%lu as key %u\0" as *const u8
                    as *const libc::c_char,
                if user.is_null() {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    user as *const libc::c_char
                },
                if user.is_null() {
                    b"\0" as *const u8 as *const libc::c_char
                } else {
                    b"@\0" as *const u8 as *const libc::c_char
                },
                host,
                crate::sshkey::sshkey_type((*hke).key),
                if want_ca != 0 {
                    b"CA \0" as *const u8 as *const libc::c_char
                } else {
                    b"\0" as *const u8 as *const libc::c_char
                },
                (*hke).file,
                (*hke).line,
                (*dch).nkeys,
            );
            (*dch).keys = crate::xmalloc::xrecallocarray(
                (*dch).keys as *mut libc::c_void,
                (*dch).nkeys as size_t,
                ((*dch).nkeys).wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
                ::core::mem::size_of::<*mut crate::sshkey::sshkey>() as libc::c_ulong,
            ) as *mut *mut crate::sshkey::sshkey;
            (*dch).key_is_ca = crate::xmalloc::xrecallocarray(
                (*dch).key_is_ca as *mut libc::c_void,
                (*dch).nkeys as size_t,
                ((*dch).nkeys).wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
                ::core::mem::size_of::<libc::c_int>() as libc::c_ulong,
            ) as *mut libc::c_int;
            r = crate::sshkey::sshkey_from_private(
                (*hke).key,
                &mut *((*dch).keys).offset((*dch).nkeys as isize),
            );
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"parse_dest_constraint_hop\0",
                    ))
                    .as_ptr(),
                    724 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"crate::sshkey::sshkey_from_private\0" as *const u8 as *const libc::c_char,
                );
            }
            *((*dch).key_is_ca).offset((*dch).nkeys as isize) = want_ca;
            (*dch).nkeys = ((*dch).nkeys).wrapping_add(1);
            (*dch).nkeys;
        }
        i = i.wrapping_add(1);
        i;
    }
    if (*dch).nkeys == 0 as libc::c_int as libc::c_uint {
        sshfatal(
            b"ssh-add.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"parse_dest_constraint_hop\0",
            ))
            .as_ptr(),
            729 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"No host keys found for destination \"%s\"\0" as *const u8 as *const libc::c_char,
            host,
        );
    }
    free_hostkeys(hostkeys);
    libc::free(os as *mut libc::c_void);
}
unsafe extern "C" fn parse_dest_constraint(
    mut s: *const libc::c_char,
    mut dcp: *mut *mut *mut dest_constraint,
    mut ndcp: *mut size_t,
    mut hostkey_files: *mut *mut libc::c_char,
) {
    let mut dc: *mut dest_constraint = 0 as *mut dest_constraint;
    let mut os: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    dc = crate::xmalloc::xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<dest_constraint>() as libc::c_ulong,
    ) as *mut dest_constraint;
    os = crate::xmalloc::xstrdup(s);
    cp = libc::strchr(os, '>' as i32);
    if cp.is_null() {
        parse_dest_constraint_hop(os, &mut (*dc).to, hostkey_files);
    } else {
        let fresh2 = cp;
        cp = cp.offset(1);
        *fresh2 = '\0' as i32 as libc::c_char;
        parse_dest_constraint_hop(os, &mut (*dc).from, hostkey_files);
        parse_dest_constraint_hop(cp, &mut (*dc).to, hostkey_files);
        if !((*dc).from.user).is_null() {
            sshfatal(
                b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"parse_dest_constraint\0",
                ))
                .as_ptr(),
                754 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"Invalid key constraint %s: cannot specify user on 'from' host\0" as *const u8
                    as *const libc::c_char,
                os,
            );
        }
    }
    crate::log::sshlog(
        b"ssh-add.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"parse_dest_constraint\0"))
            .as_ptr(),
        762 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"constraint %zu: %s%s%s (%u keys) > %s%s%s (%u keys)\0" as *const u8
            as *const libc::c_char,
        *ndcp,
        if !((*dc).from.user).is_null() {
            (*dc).from.user as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*dc).from.user).is_null() {
            b"@\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*dc).from.hostname).is_null() {
            (*dc).from.hostname as *const libc::c_char
        } else {
            b"(ORIGIN)\0" as *const u8 as *const libc::c_char
        },
        (*dc).from.nkeys,
        if !((*dc).to.user).is_null() {
            (*dc).to.user as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*dc).to.user).is_null() {
            b"@\0" as *const u8 as *const libc::c_char
        } else {
            b"\0" as *const u8 as *const libc::c_char
        },
        if !((*dc).to.hostname).is_null() {
            (*dc).to.hostname as *const libc::c_char
        } else {
            b"(ANY)\0" as *const u8 as *const libc::c_char
        },
        (*dc).to.nkeys,
    );
    *dcp = crate::xmalloc::xrecallocarray(
        *dcp as *mut libc::c_void,
        *ndcp,
        (*ndcp).wrapping_add(1 as libc::c_int as libc::c_ulong),
        ::core::mem::size_of::<*mut dest_constraint>() as libc::c_ulong,
    ) as *mut *mut dest_constraint;
    let fresh3 = *ndcp;
    *ndcp = (*ndcp).wrapping_add(1);
    let ref mut fresh4 = *(*dcp).offset(fresh3 as isize);
    *fresh4 = dc;
    libc::free(os as *mut libc::c_void);
}
unsafe extern "C" fn usage() {
    libc::fprintf(
        stderr,
        b"usage: ssh-add [-cDdKkLlqvXx] [-E fingerprint_hash] [-H hostkey_file]\n               [-h destination_constraint] [-S provider] [-t life]\n               [file ...]\n       ssh-add -s pkcs11\n       ssh-add -e pkcs11\n       ssh-add -T pubkey ...\n\0"
            as *const u8 as *const libc::c_char,
    );
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char) -> libc::c_int {
    let mut current_block: u64;
    extern "C" {
        #[link_name = "BSDoptarg"]
        static mut BSDoptarg_0: *mut libc::c_char;
    }
    extern "C" {
        #[link_name = "BSDoptind"]
        static mut BSDoptind_0: libc::c_int;
    }
    let mut agent_fd: libc::c_int = 0;
    let mut pkcs11provider: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut skprovider: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut dest_constraint_strings: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut hostkey_files: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut ch: libc::c_int = 0;
    let mut deleting: libc::c_int = 0 as libc::c_int;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut key_only: libc::c_int = 0 as libc::c_int;
    let mut do_download: libc::c_int = 0 as libc::c_int;
    let mut xflag: libc::c_int = 0 as libc::c_int;
    let mut lflag: libc::c_int = 0 as libc::c_int;
    let mut Dflag: libc::c_int = 0 as libc::c_int;
    let mut qflag: libc::c_int = 0 as libc::c_int;
    let mut Tflag: libc::c_int = 0 as libc::c_int;
    let mut log_facility: SyslogFacility = SYSLOG_FACILITY_AUTH;
    let mut log_level: LogLevel = SYSLOG_LEVEL_INFO;
    let mut dest_constraints: *mut *mut dest_constraint = 0 as *mut *mut dest_constraint;
    let mut ndest_constraints: size_t = 0 as libc::c_int as size_t;
    crate::misc::sanitise_stdfd();
    __progname =
        crate::openbsd_compat::bsd_misc::ssh_get_progname(*argv.offset(0 as libc::c_int as isize));
    seed_rng();
    log_init(__progname, log_level, log_facility, 1 as libc::c_int);
    setvbuf(
        stdout,
        0 as *mut libc::c_char,
        1 as libc::c_int,
        0 as libc::c_int as size_t,
    );
    r = ssh_get_authentication_socket(&mut agent_fd);
    match r {
        0 => {}
        -47 => {
            libc::fprintf(
                stderr,
                b"Could not open a connection to your authentication agent.\n\0" as *const u8
                    as *const libc::c_char,
            );
            libc::exit(2 as libc::c_int);
        }
        _ => {
            libc::fprintf(
                stderr,
                b"Error connecting to agent: %s\n\0" as *const u8 as *const libc::c_char,
                ssh_err(r),
            );
            libc::exit(2 as libc::c_int);
        }
    }
    skprovider = getenv(b"SSH_SK_PROVIDER\0" as *const u8 as *const libc::c_char);
    loop {
        ch = crate::openbsd_compat::getopt_long::BSDgetopt(
            argc,
            argv,
            b"vkKlLcdDTxXE:e:h:H:M:m:qs:S:t:\0" as *const u8 as *const libc::c_char,
        );
        if !(ch != -(1 as libc::c_int)) {
            current_block = 4741994311446740739;
            break;
        }
        match ch {
            118 => {
                if log_level as libc::c_int == SYSLOG_LEVEL_INFO as libc::c_int {
                    log_level = SYSLOG_LEVEL_DEBUG1;
                } else if (log_level as libc::c_int) < SYSLOG_LEVEL_DEBUG3 as libc::c_int {
                    log_level += 1;
                    log_level;
                }
            }
            69 => {
                fingerprint_hash = ssh_digest_alg_by_name(BSDoptarg);
                if fingerprint_hash == -(1 as libc::c_int) {
                    sshfatal(
                        b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        836 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"Invalid hash algorithm \"%s\"\0" as *const u8 as *const libc::c_char,
                        BSDoptarg,
                    );
                }
            }
            72 => {
                stringlist_append(&mut hostkey_files, BSDoptarg);
            }
            104 => {
                stringlist_append(&mut dest_constraint_strings, BSDoptarg);
            }
            107 => {
                key_only = 1 as libc::c_int;
            }
            75 => {
                do_download = 1 as libc::c_int;
            }
            108 | 76 => {
                if lflag != 0 as libc::c_int {
                    sshfatal(
                        b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        853 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"-%c flag already specified\0" as *const u8 as *const libc::c_char,
                        lflag,
                    );
                }
                lflag = ch;
            }
            120 | 88 => {
                if xflag != 0 as libc::c_int {
                    sshfatal(
                        b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                            .as_ptr(),
                        859 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"-%c flag already specified\0" as *const u8 as *const libc::c_char,
                        xflag,
                    );
                }
                xflag = ch;
            }
            99 => {
                confirm = 1 as libc::c_int;
            }
            109 => {
                minleft = crate::openbsd_compat::strtonum::strtonum(
                    BSDoptarg,
                    1 as libc::c_int as libc::c_longlong,
                    (2147483647 as libc::c_int as libc::c_uint)
                        .wrapping_mul(2 as libc::c_uint)
                        .wrapping_add(1 as libc::c_uint) as libc::c_longlong,
                    0 as *mut *const libc::c_char,
                ) as libc::c_int as u_int;
                if !(minleft == 0 as libc::c_int as libc::c_uint) {
                    continue;
                }
                usage();
                ret = 1 as libc::c_int;
                current_block = 12893801914756945198;
                break;
            }
            77 => {
                maxsign = crate::openbsd_compat::strtonum::strtonum(
                    BSDoptarg,
                    1 as libc::c_int as libc::c_longlong,
                    (2147483647 as libc::c_int as libc::c_uint)
                        .wrapping_mul(2 as libc::c_uint)
                        .wrapping_add(1 as libc::c_uint) as libc::c_longlong,
                    0 as *mut *const libc::c_char,
                ) as libc::c_int as u_int;
                if !(maxsign == 0 as libc::c_int as libc::c_uint) {
                    continue;
                }
                usage();
                ret = 1 as libc::c_int;
                current_block = 12893801914756945198;
                break;
            }
            100 => {
                deleting = 1 as libc::c_int;
            }
            68 => {
                Dflag = 1 as libc::c_int;
            }
            115 => {
                pkcs11provider = BSDoptarg;
            }
            83 => {
                skprovider = BSDoptarg;
            }
            101 => {
                deleting = 1 as libc::c_int;
                pkcs11provider = BSDoptarg;
            }
            116 => {
                lifetime = convtime(BSDoptarg);
                if !(lifetime == -(1 as libc::c_int)
                    || lifetime < 0 as libc::c_int
                    || lifetime as u_long > 4294967295 as libc::c_uint as libc::c_ulong)
                {
                    continue;
                }
                libc::fprintf(
                    stderr,
                    b"Invalid lifetime\n\0" as *const u8 as *const libc::c_char,
                );
                ret = 1 as libc::c_int;
                current_block = 12893801914756945198;
                break;
            }
            113 => {
                qflag = 1 as libc::c_int;
            }
            84 => {
                Tflag = 1 as libc::c_int;
            }
            _ => {
                usage();
                ret = 1 as libc::c_int;
                current_block = 12893801914756945198;
                break;
            }
        }
    }
    match current_block {
        4741994311446740739 => {
            log_init(__progname, log_level, log_facility, 1 as libc::c_int);
            if (xflag != 0 as libc::c_int) as libc::c_int
                + (lflag != 0 as libc::c_int) as libc::c_int
                + (Dflag != 0 as libc::c_int) as libc::c_int
                > 1 as libc::c_int
            {
                sshfatal(
                    b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                    920 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    0 as *const libc::c_char,
                    b"Invalid combination of actions\0" as *const u8 as *const libc::c_char,
                );
            } else if xflag != 0 {
                if lock_agent(
                    agent_fd,
                    if xflag == 'x' as i32 {
                        1 as libc::c_int
                    } else {
                        0 as libc::c_int
                    },
                ) == -(1 as libc::c_int)
                {
                    ret = 1 as libc::c_int;
                }
            } else if lflag != 0 {
                if list_identities(
                    agent_fd,
                    if lflag == 'l' as i32 {
                        1 as libc::c_int
                    } else {
                        0 as libc::c_int
                    },
                ) == -(1 as libc::c_int)
                {
                    ret = 1 as libc::c_int;
                }
            } else if Dflag != 0 {
                if delete_all(agent_fd, qflag) == -(1 as libc::c_int) {
                    ret = 1 as libc::c_int;
                }
            } else {
                if hostkey_files.is_null() {
                    stringlist_append(
                        &mut hostkey_files,
                        b"~/.ssh/known_hosts\0" as *const u8 as *const libc::c_char,
                    );
                    stringlist_append(
                        &mut hostkey_files,
                        b"~/.ssh/known_hosts2\0" as *const u8 as *const libc::c_char,
                    );
                    stringlist_append(
                        &mut hostkey_files,
                        b"/usr/local/etc/ssh_known_hosts\0" as *const u8 as *const libc::c_char,
                    );
                    stringlist_append(
                        &mut hostkey_files,
                        b"/usr/local/etc/ssh_known_hosts2\0" as *const u8 as *const libc::c_char,
                    );
                }
                if !dest_constraint_strings.is_null() {
                    i = 0 as libc::c_int;
                    while !(*dest_constraint_strings.offset(i as isize)).is_null() {
                        parse_dest_constraint(
                            *dest_constraint_strings.offset(i as isize),
                            &mut dest_constraints,
                            &mut ndest_constraints,
                            hostkey_files,
                        );
                        i += 1;
                        i;
                    }
                }
                argc -= BSDoptind;
                argv = argv.offset(BSDoptind as isize);
                if Tflag != 0 {
                    if argc <= 0 as libc::c_int {
                        sshfatal(
                            b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            958 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"no keys to test\0" as *const u8 as *const libc::c_char,
                        );
                    }
                    i = 0 as libc::c_int;
                    r = i;
                    while i < argc {
                        r |= test_key(agent_fd, *argv.offset(i as isize));
                        i += 1;
                        i;
                    }
                    ret = if r == 0 as libc::c_int {
                        0 as libc::c_int
                    } else {
                        1 as libc::c_int
                    };
                } else if !pkcs11provider.is_null() {
                    if update_card(
                        agent_fd,
                        (deleting == 0) as libc::c_int,
                        pkcs11provider,
                        qflag,
                        dest_constraints,
                        ndest_constraints,
                    ) == -(1 as libc::c_int)
                    {
                        ret = 1 as libc::c_int;
                    }
                } else if do_download != 0 {
                    if skprovider.is_null() {
                        sshfatal(
                            b"ssh-add.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0"))
                                .as_ptr(),
                            972 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_FATAL,
                            0 as *const libc::c_char,
                            b"Cannot download keys without provider\0" as *const u8
                                as *const libc::c_char,
                        );
                    }
                    if load_resident_keys(
                        agent_fd,
                        skprovider,
                        qflag,
                        dest_constraints,
                        ndest_constraints,
                    ) != 0 as libc::c_int
                    {
                        ret = 1 as libc::c_int;
                    }
                } else if argc == 0 as libc::c_int {
                    let mut buf: [libc::c_char; 4096] = [0; 4096];
                    let mut pw: *mut libc::passwd = 0 as *mut libc::passwd;
                    let mut st: libc::stat = unsafe { std::mem::zeroed() };
                    let mut count: libc::c_int = 0 as libc::c_int;
                    pw = libc::getpwuid(libc::getuid());
                    if pw.is_null() {
                        libc::fprintf(
                            stderr,
                            b"No user found with uid %u\n\0" as *const u8 as *const libc::c_char,
                            libc::getuid(),
                        );
                        ret = 1 as libc::c_int;
                    } else {
                        i = 0 as libc::c_int;
                        while !(default_files[i as usize]).is_null() {
                            libc::snprintf(
                                buf.as_mut_ptr(),
                                ::core::mem::size_of::<[libc::c_char; 4096]>() as usize,
                                b"%s/%s\0" as *const u8 as *const libc::c_char,
                                (*pw).pw_dir,
                                default_files[i as usize],
                            );
                            if !(libc::stat(buf.as_mut_ptr(), &mut st) == -(1 as libc::c_int)) {
                                if do_file(
                                    agent_fd,
                                    deleting,
                                    key_only,
                                    buf.as_mut_ptr(),
                                    qflag,
                                    skprovider,
                                    dest_constraints,
                                    ndest_constraints,
                                ) == -(1 as libc::c_int)
                                {
                                    ret = 1 as libc::c_int;
                                } else {
                                    count += 1;
                                    count;
                                }
                            }
                            i += 1;
                            i;
                        }
                        if count == 0 as libc::c_int {
                            ret = 1 as libc::c_int;
                        }
                    }
                } else {
                    i = 0 as libc::c_int;
                    while i < argc {
                        if do_file(
                            agent_fd,
                            deleting,
                            key_only,
                            *argv.offset(i as isize),
                            qflag,
                            skprovider,
                            dest_constraints,
                            ndest_constraints,
                        ) == -(1 as libc::c_int)
                        {
                            ret = 1 as libc::c_int;
                        }
                        i += 1;
                        i;
                    }
                }
            }
        }
        _ => {}
    }
    clear_pass();
    ssh_close_authentication_socket(agent_fd);
    return ret;
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
