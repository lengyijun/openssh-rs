use ::libc;
use libc::close;

extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type sshbuf;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut libc::FILE;

    fn getuid() -> __uid_t;
    fn fclose(__stream: *mut libc::FILE) -> libc::c_int;

    fn asprintf(__ptr: *mut *mut libc::c_char, __fmt: *const libc::c_char, _: ...) -> libc::c_int;
    fn __getdelim(
        __lineptr: *mut *mut libc::c_char,
        __n: *mut size_t,
        __delimiter: libc::c_int,
        __stream: *mut libc::FILE,
    ) -> __ssize_t;
    fn ferror(__stream: *mut libc::FILE) -> libc::c_int;

    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn strcspn(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_ulong;

    fn sshkey_new(_: libc::c_int) -> *mut sshkey;
    fn sshkey_write(_: *const sshkey, _: *mut libc::FILE) -> libc::c_int;
    fn sshkey_private_to_fileblob(
        key: *mut sshkey,
        blob: *mut sshbuf,
        passphrase: *const libc::c_char,
        comment: *const libc::c_char,
        format: libc::c_int,
        openssh_format_cipher: *const libc::c_char,
        openssh_format_rounds: libc::c_int,
    ) -> libc::c_int;
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_read(_: *mut sshkey, _: *mut *mut libc::c_char) -> libc::c_int;
    fn sshkey_is_cert(_: *const sshkey) -> libc::c_int;
    fn sshkey_equal(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_equal_public(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_to_certified(_: *mut sshkey) -> libc::c_int;
    fn sshkey_cert_copy(_: *const sshkey, _: *mut sshkey) -> libc::c_int;
    fn sshkey_parse_private_fileblob_type(
        blob: *mut sshbuf,
        type_0: libc::c_int,
        passphrase: *const libc::c_char,
        keyp: *mut *mut sshkey,
        commentp: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sshkey_parse_pubkey_from_private_fileblob_type(
        blob: *mut sshbuf,
        type_0: libc::c_int,
        pubkeyp: *mut *mut sshkey,
    ) -> libc::c_int;
    fn sshkey_set_filename(_: *mut sshkey, _: *const libc::c_char) -> libc::c_int;
    fn sshbuf_new() -> *mut sshbuf;
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_load_fd(_: libc::c_int, _: *mut *mut sshbuf) -> libc::c_int;
    fn sshbuf_write_file(path: *const libc::c_char, buf: *mut sshbuf) -> libc::c_int;
    fn ssh_krl_file_contains_key(path: *const libc::c_char, key: *const sshkey) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
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
pub type mode_t = __mode_t;
pub type size_t = libc::c_ulong;
pub type u_int64_t = __uint64_t;

pub type uint8_t = __uint8_t;

pub type _IO_lock_t = ();

pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type EC_KEY = ec_key_st;
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
pub const KEY_UNSPEC: sshkey_types = 14;
pub const KEY_XMSS: sshkey_types = 8;
pub const KEY_ED25519: sshkey_types = 3;
pub const KEY_ECDSA: sshkey_types = 2;
pub const KEY_DSA: sshkey_types = 1;
pub const KEY_RSA: sshkey_types = 0;
pub type sshkey_types = libc::c_uint;
pub const KEY_ED25519_SK_CERT: sshkey_types = 13;
pub const KEY_ED25519_SK: sshkey_types = 12;
pub const KEY_ECDSA_SK_CERT: sshkey_types = 11;
pub const KEY_ECDSA_SK: sshkey_types = 10;
pub const KEY_XMSS_CERT: sshkey_types = 9;
pub const KEY_ED25519_CERT: sshkey_types = 7;
pub const KEY_ECDSA_CERT: sshkey_types = 6;
pub const KEY_DSA_CERT: sshkey_types = 5;
pub const KEY_RSA_CERT: sshkey_types = 4;
#[inline]
unsafe extern "C" fn getline(
    mut __lineptr: *mut *mut libc::c_char,
    mut __n: *mut size_t,
    mut __stream: *mut libc::FILE,
) -> __ssize_t {
    return __getdelim(__lineptr, __n, '\n' as i32, __stream);
}
unsafe extern "C" fn sshkey_save_private_blob(
    mut keybuf: *mut sshbuf,
    mut filename: *const libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    let mut omask: mode_t = 0;
    omask = libc::umask(0o77 as libc::c_int as __mode_t);
    r = sshbuf_write_file(filename, keybuf);
    libc::umask(omask);
    return r;
}
pub unsafe extern "C" fn sshkey_save_private(
    mut key: *mut sshkey,
    mut filename: *const libc::c_char,
    mut passphrase: *const libc::c_char,
    mut comment: *const libc::c_char,
    mut format: libc::c_int,
    mut openssh_format_cipher: *const libc::c_char,
    mut openssh_format_rounds: libc::c_int,
) -> libc::c_int {
    let mut keyblob: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    keyblob = sshbuf_new();
    if keyblob.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshkey_private_to_fileblob(
        key,
        keyblob,
        passphrase,
        comment,
        format,
        openssh_format_cipher,
        openssh_format_rounds,
    );
    if !(r != 0 as libc::c_int) {
        r = sshkey_save_private_blob(keyblob, filename);
        if !(r != 0 as libc::c_int) {
            r = 0 as libc::c_int;
        }
    }
    sshbuf_free(keyblob);
    return r;
}
pub unsafe extern "C" fn sshkey_perm_ok(
    mut fd: libc::c_int,
    mut filename: *const libc::c_char,
) -> libc::c_int {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if libc::fstat(fd, &mut st) == -(1 as libc::c_int) {
        return -(24 as libc::c_int);
    }
    if st.st_uid == getuid()
        && st.st_mode & 0o77 as libc::c_int as libc::c_uint != 0 as libc::c_int as libc::c_uint
    {
        crate::log::sshlog(
            b"authfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sshkey_perm_ok\0"))
                .as_ptr(),
            105 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\0" as *const u8
                as *const libc::c_char,
        );
        crate::log::sshlog(
            b"authfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sshkey_perm_ok\0"))
                .as_ptr(),
            106 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"@         WARNING: UNPROTECTED PRIVATE KEY libc::FILE!          @\0" as *const u8
                as *const libc::c_char,
        );
        crate::log::sshlog(
            b"authfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sshkey_perm_ok\0"))
                .as_ptr(),
            107 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\0" as *const u8
                as *const libc::c_char,
        );
        crate::log::sshlog(
            b"authfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sshkey_perm_ok\0"))
                .as_ptr(),
            109 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"Permissions 0%3.3o for '%s' are too open.\0" as *const u8 as *const libc::c_char,
            st.st_mode & 0o777 as libc::c_int as libc::c_uint,
            filename,
        );
        crate::log::sshlog(
            b"authfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sshkey_perm_ok\0"))
                .as_ptr(),
            110 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"It is required that your private key files are NOT accessible by others.\0"
                as *const u8 as *const libc::c_char,
        );
        crate::log::sshlog(
            b"authfile.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"sshkey_perm_ok\0"))
                .as_ptr(),
            111 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"This private key will be ignored.\0" as *const u8 as *const libc::c_char,
        );
        return -(44 as libc::c_int);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn sshkey_load_private_type(
    mut type_0: libc::c_int,
    mut filename: *const libc::c_char,
    mut passphrase: *const libc::c_char,
    mut keyp: *mut *mut sshkey,
    mut commentp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut fd: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    if !keyp.is_null() {
        *keyp = 0 as *mut sshkey;
    }
    if !commentp.is_null() {
        *commentp = 0 as *mut libc::c_char;
    }
    fd = libc::open(filename, 0 as libc::c_int);
    if fd == -(1 as libc::c_int) {
        return -(24 as libc::c_int);
    }
    r = sshkey_perm_ok(fd, filename);
    if !(r != 0 as libc::c_int) {
        r = sshkey_load_private_type_fd(fd, type_0, passphrase, keyp, commentp);
        if r == 0 as libc::c_int && !keyp.is_null() && !(*keyp).is_null() {
            r = sshkey_set_filename(*keyp, filename);
        }
    }
    close(fd);
    return r;
}
pub unsafe extern "C" fn sshkey_load_private(
    mut filename: *const libc::c_char,
    mut passphrase: *const libc::c_char,
    mut keyp: *mut *mut sshkey,
    mut commentp: *mut *mut libc::c_char,
) -> libc::c_int {
    return sshkey_load_private_type(
        KEY_UNSPEC as libc::c_int,
        filename,
        passphrase,
        keyp,
        commentp,
    );
}
pub unsafe extern "C" fn sshkey_load_private_type_fd(
    mut fd: libc::c_int,
    mut type_0: libc::c_int,
    mut passphrase: *const libc::c_char,
    mut keyp: *mut *mut sshkey,
    mut commentp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut buffer: *mut sshbuf = 0 as *mut sshbuf;
    let mut r: libc::c_int = 0;
    if !keyp.is_null() {
        *keyp = 0 as *mut sshkey;
    }
    r = sshbuf_load_fd(fd, &mut buffer);
    if !(r != 0 as libc::c_int || {
        r = sshkey_parse_private_fileblob_type(buffer, type_0, passphrase, keyp, commentp);
        r != 0 as libc::c_int
    }) {
        r = 0 as libc::c_int;
    }
    sshbuf_free(buffer);
    return r;
}
unsafe extern "C" fn sshkey_load_pubkey_from_private(
    mut filename: *const libc::c_char,
    mut pubkeyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut buffer: *mut sshbuf = 0 as *mut sshbuf;
    let mut pubkey: *mut sshkey = 0 as *mut sshkey;
    let mut r: libc::c_int = 0;
    let mut fd: libc::c_int = 0;
    if !pubkeyp.is_null() {
        *pubkeyp = 0 as *mut sshkey;
    }
    fd = libc::open(filename, 0 as libc::c_int);
    if fd == -(1 as libc::c_int) {
        return -(24 as libc::c_int);
    }
    r = sshbuf_load_fd(fd, &mut buffer);
    if !(r != 0 as libc::c_int || {
        r = sshkey_parse_pubkey_from_private_fileblob_type(
            buffer,
            KEY_UNSPEC as libc::c_int,
            &mut pubkey,
        );
        r != 0 as libc::c_int
    }) {
        r = sshkey_set_filename(pubkey, filename);
        if !(r != 0 as libc::c_int) {
            if !pubkeyp.is_null() {
                *pubkeyp = pubkey;
                pubkey = 0 as *mut sshkey;
            }
            r = 0 as libc::c_int;
        }
    }
    close(fd);
    sshbuf_free(buffer);
    sshkey_free(pubkey);
    return r;
}
unsafe extern "C" fn sshkey_try_load_public(
    mut kp: *mut *mut sshkey,
    mut filename: *const libc::c_char,
    mut commentp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    let mut k: *mut sshkey = 0 as *mut sshkey;
    if kp.is_null() {
        return -(10 as libc::c_int);
    }
    *kp = 0 as *mut sshkey;
    if !commentp.is_null() {
        *commentp = 0 as *mut libc::c_char;
    }
    f = fopen(filename, b"r\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        return -(24 as libc::c_int);
    }
    k = sshkey_new(KEY_UNSPEC as libc::c_int);
    if k.is_null() {
        fclose(f);
        return -(2 as libc::c_int);
    }
    while getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long {
        cp = line;
        match *cp as libc::c_int {
            35 | 10 | 0 => {
                continue;
            }
            _ => {}
        }
        if strncmp(
            cp,
            b"-----BEGIN\0" as *const u8 as *const libc::c_char,
            10 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
            || strcmp(
                cp,
                b"SSH PRIVATE KEY libc::FILE\0" as *const u8 as *const libc::c_char,
            ) == 0 as libc::c_int
        {
            break;
        }
        while *cp as libc::c_int != 0
            && (*cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32)
        {
            cp = cp.offset(1);
            cp;
        }
        if *cp != 0 {
            r = sshkey_read(k, &mut cp);
            if r == 0 as libc::c_int {
                *cp.offset(strcspn(cp, b"\r\n\0" as *const u8 as *const libc::c_char) as isize) =
                    '\0' as i32 as libc::c_char;
                if !commentp.is_null() {
                    *commentp = strdup(if *cp as libc::c_int != 0 {
                        cp as *const libc::c_char
                    } else {
                        filename
                    });
                    if (*commentp).is_null() {
                        r = -(2 as libc::c_int);
                    }
                }
                *kp = k;
                libc::free(line as *mut libc::c_void);
                fclose(f);
                return r;
            }
        }
    }
    libc::free(k as *mut libc::c_void);
    libc::free(line as *mut libc::c_void);
    fclose(f);
    return -(4 as libc::c_int);
}
pub unsafe extern "C" fn sshkey_load_public(
    mut filename: *const libc::c_char,
    mut keyp: *mut *mut sshkey,
    mut commentp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut pubfile: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    if !keyp.is_null() {
        *keyp = 0 as *mut sshkey;
    }
    if !commentp.is_null() {
        *commentp = 0 as *mut libc::c_char;
    }
    r = sshkey_try_load_public(keyp, filename, commentp);
    if !(r == 0 as libc::c_int) {
        if asprintf(
            &mut pubfile as *mut *mut libc::c_char,
            b"%s.pub\0" as *const u8 as *const libc::c_char,
            filename,
        ) == -(1 as libc::c_int)
        {
            return -(2 as libc::c_int);
        }
        r = sshkey_try_load_public(keyp, pubfile, commentp);
        if !(r == 0 as libc::c_int) {
            r = sshkey_load_pubkey_from_private(filename, keyp);
            if !(r == 0 as libc::c_int) {
                r = -(24 as libc::c_int);
                *libc::__errno_location() = 2 as libc::c_int;
            }
        }
    }
    oerrno = *libc::__errno_location();
    libc::free(pubfile as *mut libc::c_void);
    *libc::__errno_location() = oerrno;
    return r;
}
pub unsafe extern "C" fn sshkey_load_cert(
    mut filename: *const libc::c_char,
    mut keyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut pub_0: *mut sshkey = 0 as *mut sshkey;
    let mut file: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut r: libc::c_int = -(1 as libc::c_int);
    if !keyp.is_null() {
        *keyp = 0 as *mut sshkey;
    }
    if asprintf(
        &mut file as *mut *mut libc::c_char,
        b"%s-cert.pub\0" as *const u8 as *const libc::c_char,
        filename,
    ) == -(1 as libc::c_int)
    {
        return -(2 as libc::c_int);
    }
    r = sshkey_try_load_public(keyp, file, 0 as *mut *mut libc::c_char);
    libc::free(file as *mut libc::c_void);
    sshkey_free(pub_0);
    return r;
}
pub unsafe extern "C" fn sshkey_load_private_cert(
    mut type_0: libc::c_int,
    mut filename: *const libc::c_char,
    mut passphrase: *const libc::c_char,
    mut keyp: *mut *mut sshkey,
) -> libc::c_int {
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut cert: *mut sshkey = 0 as *mut sshkey;
    let mut r: libc::c_int = 0;
    if !keyp.is_null() {
        *keyp = 0 as *mut sshkey;
    }
    match type_0 {
        0 | 1 | 2 | 3 | 8 | 14 => {}
        _ => return -(14 as libc::c_int),
    }
    r = sshkey_load_private_type(
        type_0,
        filename,
        passphrase,
        &mut key,
        0 as *mut *mut libc::c_char,
    );
    if !(r != 0 as libc::c_int || {
        r = sshkey_load_cert(filename, &mut cert);
        r != 0 as libc::c_int
    }) {
        if sshkey_equal_public(key, cert) == 0 as libc::c_int {
            r = -(45 as libc::c_int);
        } else {
            r = sshkey_to_certified(key);
            if !(r != 0 as libc::c_int || {
                r = sshkey_cert_copy(cert, key);
                r != 0 as libc::c_int
            }) {
                r = 0 as libc::c_int;
                if !keyp.is_null() {
                    *keyp = key;
                    key = 0 as *mut sshkey;
                }
            }
        }
    }
    sshkey_free(key);
    sshkey_free(cert);
    return r;
}
pub unsafe extern "C" fn sshkey_in_file(
    mut key: *mut sshkey,
    mut filename: *const libc::c_char,
    mut strict_type: libc::c_int,
    mut check_ca: libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut line: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut cp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut linesize: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0 as libc::c_int;
    let mut pub_0: *mut sshkey = 0 as *mut sshkey;
    let mut sshkey_compare: Option<
        unsafe extern "C" fn(*const sshkey, *const sshkey) -> libc::c_int,
    > = if strict_type != 0 {
        Some(sshkey_equal as unsafe extern "C" fn(*const sshkey, *const sshkey) -> libc::c_int)
    } else {
        Some(
            sshkey_equal_public
                as unsafe extern "C" fn(*const sshkey, *const sshkey) -> libc::c_int,
        )
    };
    f = fopen(filename, b"r\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        return -(24 as libc::c_int);
    }
    loop {
        if !(getline(&mut line, &mut linesize, f) != -(1 as libc::c_int) as libc::c_long) {
            current_block = 6009453772311597924;
            break;
        }
        sshkey_free(pub_0);
        pub_0 = 0 as *mut sshkey;
        cp = line;
        while *cp as libc::c_int != 0
            && (*cp as libc::c_int == ' ' as i32 || *cp as libc::c_int == '\t' as i32)
        {
            cp = cp.offset(1);
            cp;
        }
        match *cp as libc::c_int {
            35 | 10 | 0 => {
                continue;
            }
            _ => {}
        }
        pub_0 = sshkey_new(KEY_UNSPEC as libc::c_int);
        if pub_0.is_null() {
            r = -(2 as libc::c_int);
            current_block = 8515232886190949647;
            break;
        } else {
            r = sshkey_read(pub_0, &mut cp);
            match r {
                0 => {}
                -56 => {
                    continue;
                }
                _ => {
                    current_block = 8515232886190949647;
                    break;
                }
            }
            if !(sshkey_compare.expect("non-null function pointer")(key, pub_0) != 0
                || check_ca != 0
                    && sshkey_is_cert(key) != 0
                    && sshkey_compare.expect("non-null function pointer")(
                        (*(*key).cert).signature_key,
                        pub_0,
                    ) != 0)
            {
                continue;
            }
            r = 0 as libc::c_int;
            current_block = 8515232886190949647;
            break;
        }
    }
    match current_block {
        6009453772311597924 => {
            r = -(46 as libc::c_int);
        }
        _ => {}
    }
    libc::free(line as *mut libc::c_void);
    sshkey_free(pub_0);
    fclose(f);
    return r;
}
pub unsafe extern "C" fn sshkey_check_revoked(
    mut key: *mut sshkey,
    mut revoked_keys_file: *const libc::c_char,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = ssh_krl_file_contains_key(revoked_keys_file, key);
    if r != -(50 as libc::c_int) {
        return r;
    }
    r = sshkey_in_file(key, revoked_keys_file, 0 as libc::c_int, 1 as libc::c_int);
    match r {
        0 => return -(51 as libc::c_int),
        -46 => return 0 as libc::c_int,
        _ => return r,
    };
}
pub unsafe extern "C" fn sshkey_advance_past_options(
    mut cpp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut cp: *mut libc::c_char = *cpp;
    let mut quoted: libc::c_int = 0 as libc::c_int;
    while *cp as libc::c_int != 0
        && (quoted != 0 || *cp as libc::c_int != ' ' as i32 && *cp as libc::c_int != '\t' as i32)
    {
        if *cp as libc::c_int == '\\' as i32
            && *cp.offset(1 as libc::c_int as isize) as libc::c_int == '"' as i32
        {
            cp = cp.offset(1);
            cp;
        } else if *cp as libc::c_int == '"' as i32 {
            quoted = (quoted == 0) as libc::c_int;
        }
        cp = cp.offset(1);
        cp;
    }
    *cpp = cp;
    return if *cp as libc::c_int == '\0' as i32 && quoted != 0 {
        -(1 as libc::c_int)
    } else {
        0 as libc::c_int
    };
}
pub unsafe extern "C" fn sshkey_save_public(
    mut key: *const sshkey,
    mut path: *const libc::c_char,
    mut comment: *const libc::c_char,
) -> libc::c_int {
    let mut fd: libc::c_int = 0;
    let mut oerrno: libc::c_int = 0;
    let mut f: *mut libc::FILE = 0 as *mut libc::FILE;
    let mut r: libc::c_int = -(1 as libc::c_int);
    fd = libc::open(
        path,
        0o1 as libc::c_int | 0o100 as libc::c_int | 0o1000 as libc::c_int,
        0o644 as libc::c_int,
    );
    if fd == -(1 as libc::c_int) {
        return -(24 as libc::c_int);
    }
    f = libc::fdopen(fd, b"w\0" as *const u8 as *const libc::c_char);
    if f.is_null() {
        r = -(24 as libc::c_int);
        close(fd);
    } else {
        r = sshkey_write(key, f);
        if !(r != 0 as libc::c_int) {
            libc::fprintf(f, b" %s\n\0" as *const u8 as *const libc::c_char, comment);
            if ferror(f) != 0 {
                r = -(24 as libc::c_int);
            } else if fclose(f) != 0 as libc::c_int {
                r = -(24 as libc::c_int);
                f = 0 as *mut libc::FILE;
            } else {
                return 0 as libc::c_int;
            }
        }
    }
    if !f.is_null() {
        oerrno = *libc::__errno_location();
        fclose(f);
        *libc::__errno_location() = oerrno;
    }
    return r;
}
