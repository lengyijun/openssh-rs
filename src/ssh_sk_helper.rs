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
    fn __errno_location() -> *mut libc::c_int;
    
    fn closefrom(__lowfd: libc::c_int);
    fn dup(__fd: libc::c_int) -> libc::c_int;
    fn BSDgetopt(
        ___argc: libc::c_int,
        ___argv: *const *mut libc::c_char,
        __shortopts: *const libc::c_char,
    ) -> libc::c_int;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn freezero(_: *mut libc::c_void, _: size_t);
    fn free(_: *mut libc::c_void);
    fn exit(_: libc::c_int) -> !;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn strerror(_: libc::c_int) -> *mut libc::c_char;
    fn xvasprintf(
        _: *mut *mut libc::c_char,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn log_init(_: *const libc::c_char, _: LogLevel, _: SyslogFacility, _: libc::c_int);
    fn log_level_name(_: LogLevel) -> *const libc::c_char;
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
    fn sshkey_private_deserialize(buf: *mut sshbuf, keyp: *mut *mut sshkey) -> libc::c_int;
    fn sshkey_private_serialize(key: *mut sshkey, buf: *mut sshbuf) -> libc::c_int;
    fn sshkey_ssh_name(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_is_sk(_: *const sshkey) -> libc::c_int;
    fn sshkey_type(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_free(_: *mut sshkey);
    fn sanitise_stdfd();
    fn sshbuf_new() -> *mut sshbuf;
    fn sshbuf_froms(buf: *mut sshbuf, bufp: *mut *mut sshbuf) -> libc::c_int;
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_reset(buf: *mut sshbuf);
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_get_u32(buf: *mut sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_put_u32(buf: *mut sshbuf, val: u_int32_t) -> libc::c_int;
    fn sshbuf_get_cstring(
        buf: *mut sshbuf,
        valp: *mut *mut libc::c_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_string(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_put_cstring(buf: *mut sshbuf, v: *const libc::c_char) -> libc::c_int;
    fn sshbuf_put_stringb(buf: *mut sshbuf, v: *const sshbuf) -> libc::c_int;
    fn sshbuf_get_string_direct(
        buf: *mut sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn ssh_msg_send(_: libc::c_int, _: u_char, _: *mut sshbuf) -> libc::c_int;
    fn ssh_msg_recv(_: libc::c_int, _: *mut sshbuf) -> libc::c_int;
    fn sshsk_enroll(
        type_0: libc::c_int,
        provider_path: *const libc::c_char,
        device: *const libc::c_char,
        application: *const libc::c_char,
        userid: *const libc::c_char,
        flags: uint8_t,
        pin: *const libc::c_char,
        challenge_buf: *mut sshbuf,
        keyp: *mut *mut sshkey,
        attest: *mut sshbuf,
    ) -> libc::c_int;
    fn sshsk_sign(
        provider_path: *const libc::c_char,
        key: *mut sshkey,
        sigp: *mut *mut u_char,
        lenp: *mut size_t,
        data: *const u_char,
        datalen: size_t,
        compat: u_int,
        pin: *const libc::c_char,
    ) -> libc::c_int;
    fn sshsk_load_resident(
        provider_path: *const libc::c_char,
        device: *const libc::c_char,
        pin: *const libc::c_char,
        flags: u_int,
        srksp: *mut *mut *mut sshsk_resident_key,
        nsrksp: *mut size_t,
    ) -> libc::c_int;
    fn sshsk_free_resident_keys(srks: *mut *mut sshsk_resident_key, nsrks: size_t);
    static mut __progname: *mut libc::c_char;
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
pub type __u_long = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;
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
pub type va_list = __builtin_va_list;
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
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type EC_KEY = ec_key_st;
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
pub struct sshsk_resident_key {
    pub key: *mut sshkey,
    pub user_id: *mut uint8_t,
    pub user_id_len: size_t,
}
unsafe extern "C" fn reply_error(
    mut r: libc::c_int,
    mut fmt: *mut libc::c_char,
    mut args: ...
) -> *mut sshbuf {
    let mut msg: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ap: ::core::ffi::VaListImpl;
    let mut resp: *mut sshbuf = 0 as *mut sshbuf;
    ap = args.clone();
    xvasprintf(&mut msg, fmt, ap.as_va_list());
    sshlog(
        b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"reply_error\0")).as_ptr(),
        65 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"%s: %s\0" as *const u8 as *const libc::c_char,
        __progname,
        msg,
    );
    free(msg as *mut libc::c_void);
    if r >= 0 as libc::c_int {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"reply_error\0")).as_ptr(),
            69 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"invalid error code %d\0" as *const u8 as *const libc::c_char,
            r,
        );
    }
    resp = sshbuf_new();
    if resp.is_null() {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"reply_error\0")).as_ptr(),
            72 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: sshbuf_new failed\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if sshbuf_put_u32(resp, 0 as libc::c_int as u_int32_t) != 0 as libc::c_int
        || sshbuf_put_u32(resp, -r as u_int) != 0 as libc::c_int
    {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"reply_error\0")).as_ptr(),
            75 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: buffer error\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    return resp;
}
unsafe extern "C" fn null_empty(mut s: *mut *mut libc::c_char) {
    if s.is_null() || (*s).is_null() || **s as libc::c_int != '\0' as i32 {
        return;
    }
    free(*s as *mut libc::c_void);
    *s = 0 as *mut libc::c_char;
}
unsafe extern "C" fn process_sign(mut req: *mut sshbuf) -> *mut sshbuf {
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut resp: *mut sshbuf = 0 as *mut sshbuf;
    let mut kbuf: *mut sshbuf = 0 as *mut sshbuf;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut compat: uint32_t = 0;
    let mut message: *const u_char = 0 as *const u_char;
    let mut sig: *mut u_char = 0 as *mut u_char;
    let mut msglen: size_t = 0;
    let mut siglen: size_t = 0 as libc::c_int as size_t;
    let mut provider: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    r = sshbuf_froms(req, &mut kbuf);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_cstring(req, &mut provider, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_string_direct(req, &mut message, &mut msglen);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_cstring(req, 0 as *mut *mut libc::c_char, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(req, &mut compat);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_cstring(req, &mut pin, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_sign\0")).as_ptr(),
            108 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"%s: parse\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if sshbuf_len(req) != 0 as libc::c_int as libc::c_ulong {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_sign\0")).as_ptr(),
            110 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: trailing data in request\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    r = sshkey_private_deserialize(kbuf, &mut key);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_sign\0")).as_ptr(),
            113 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"%s: Unable to parse private key\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if sshkey_is_sk(key) == 0 {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_sign\0")).as_ptr(),
            116 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: Unsupported key type %s\0" as *const u8 as *const libc::c_char,
            __progname,
            sshkey_ssh_name(key),
        );
    }
    sshlog(
        b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_sign\0")).as_ptr(),
        121 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"ready to sign with key %s, provider %s: msg len %zu, compat 0x%lx\0" as *const u8
            as *const libc::c_char,
        sshkey_type(key),
        provider,
        msglen,
        compat as u_long,
    );
    null_empty(&mut pin);
    r = sshsk_sign(
        provider,
        key,
        &mut sig,
        &mut siglen,
        message,
        msglen,
        compat,
        pin,
    );
    if r != 0 as libc::c_int {
        resp = reply_error(
            r,
            b"Signing failed: %s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            ssh_err(r),
        );
    } else {
        resp = sshbuf_new();
        if resp.is_null() {
            sshfatal(
                b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_sign\0"))
                    .as_ptr(),
                132 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s: sshbuf_new failed\0" as *const u8 as *const libc::c_char,
                __progname,
            );
        }
        r = sshbuf_put_u32(resp, 1 as libc::c_int as u_int32_t);
        if r != 0 as libc::c_int || {
            r = sshbuf_put_string(resp, sig as *const libc::c_void, siglen);
            r != 0 as libc::c_int
        } {
            sshfatal(
                b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"process_sign\0"))
                    .as_ptr(),
                136 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"%s: compose\0" as *const u8 as *const libc::c_char,
                __progname,
            );
        }
    }
    sshkey_free(key);
    sshbuf_free(kbuf);
    free(provider as *mut libc::c_void);
    if !sig.is_null() {
        freezero(sig as *mut libc::c_void, siglen);
    }
    if !pin.is_null() {
        freezero(pin as *mut libc::c_void, strlen(pin));
    }
    return resp;
}
unsafe extern "C" fn process_enroll(mut req: *mut sshbuf) -> *mut sshbuf {
    let mut r: libc::c_int = 0;
    let mut type_0: u_int = 0;
    let mut provider: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut application: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut device: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut userid: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut flags: uint8_t = 0;
    let mut challenge: *mut sshbuf = 0 as *mut sshbuf;
    let mut attest: *mut sshbuf = 0 as *mut sshbuf;
    let mut kbuf: *mut sshbuf = 0 as *mut sshbuf;
    let mut resp: *mut sshbuf = 0 as *mut sshbuf;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    attest = sshbuf_new();
    if attest.is_null() || {
        kbuf = sshbuf_new();
        kbuf.is_null()
    } {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_enroll\0"))
                .as_ptr(),
            160 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: sshbuf_new failed\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    r = sshbuf_get_u32(req, &mut type_0);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_cstring(req, &mut provider, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_cstring(req, &mut device, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_cstring(req, &mut application, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_cstring(req, &mut userid, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u8(req, &mut flags);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_cstring(req, &mut pin, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_froms(req, &mut challenge);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_enroll\0"))
                .as_ptr(),
            170 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"%s: parse\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if sshbuf_len(req) != 0 as libc::c_int as libc::c_ulong {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_enroll\0"))
                .as_ptr(),
            172 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: trailing data in request\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if type_0 > 2147483647 as libc::c_int as libc::c_uint {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_enroll\0"))
                .as_ptr(),
            175 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: bad type %u\0" as *const u8 as *const libc::c_char,
            __progname,
            type_0,
        );
    }
    if sshbuf_len(challenge) == 0 as libc::c_int as libc::c_ulong {
        sshbuf_free(challenge);
        challenge = 0 as *mut sshbuf;
    }
    null_empty(&mut device);
    null_empty(&mut userid);
    null_empty(&mut pin);
    r = sshsk_enroll(
        type_0 as libc::c_int,
        provider,
        device,
        application,
        userid,
        flags,
        pin,
        challenge,
        &mut key,
        attest,
    );
    if r != 0 as libc::c_int {
        resp = reply_error(
            r,
            b"Enrollment failed: %s\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
            ssh_err(r),
        );
    } else {
        resp = sshbuf_new();
        if resp.is_null() {
            sshfatal(
                b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_enroll\0"))
                    .as_ptr(),
                191 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s: sshbuf_new failed\0" as *const u8 as *const libc::c_char,
                __progname,
            );
        }
        r = sshkey_private_serialize(key, kbuf);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_enroll\0"))
                    .as_ptr(),
                193 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"%s: encode key\0" as *const u8 as *const libc::c_char,
                __progname,
            );
        }
        r = sshbuf_put_u32(resp, 2 as libc::c_int as u_int32_t);
        if r != 0 as libc::c_int
            || {
                r = sshbuf_put_stringb(resp, kbuf);
                r != 0 as libc::c_int
            }
            || {
                r = sshbuf_put_stringb(resp, attest);
                r != 0 as libc::c_int
            }
        {
            sshfatal(
                b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"process_enroll\0"))
                    .as_ptr(),
                197 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"%s: compose\0" as *const u8 as *const libc::c_char,
                __progname,
            );
        }
    }
    sshkey_free(key);
    sshbuf_free(kbuf);
    sshbuf_free(attest);
    sshbuf_free(challenge);
    free(provider as *mut libc::c_void);
    free(application as *mut libc::c_void);
    if !pin.is_null() {
        freezero(pin as *mut libc::c_void, strlen(pin));
    }
    return resp;
}
unsafe extern "C" fn process_load_resident(mut req: *mut sshbuf) -> *mut sshbuf {
    let mut r: libc::c_int = 0;
    let mut provider: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut device: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut kbuf: *mut sshbuf = 0 as *mut sshbuf;
    let mut resp: *mut sshbuf = 0 as *mut sshbuf;
    let mut srks: *mut *mut sshsk_resident_key = 0 as *mut *mut sshsk_resident_key;
    let mut nsrks: size_t = 0 as libc::c_int as size_t;
    let mut i: size_t = 0;
    let mut flags: u_int = 0;
    kbuf = sshbuf_new();
    if kbuf.is_null() {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"process_load_resident\0"))
                .as_ptr(),
            223 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: sshbuf_new failed\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    r = sshbuf_get_cstring(req, &mut provider, 0 as *mut size_t);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_cstring(req, &mut device, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_cstring(req, &mut pin, 0 as *mut size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(req, &mut flags);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"process_load_resident\0"))
                .as_ptr(),
            229 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"%s: parse\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if sshbuf_len(req) != 0 as libc::c_int as libc::c_ulong {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"process_load_resident\0"))
                .as_ptr(),
            231 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: trailing data in request\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    null_empty(&mut device);
    null_empty(&mut pin);
    r = sshsk_load_resident(provider, device, pin, flags, &mut srks, &mut nsrks);
    if r != 0 as libc::c_int {
        resp = reply_error(
            r,
            b"sshsk_load_resident failed: %s\0" as *const u8 as *const libc::c_char
                as *mut libc::c_char,
            ssh_err(r),
        );
    } else {
        resp = sshbuf_new();
        if resp.is_null() {
            sshfatal(
                b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"process_load_resident\0",
                ))
                .as_ptr(),
                244 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s: sshbuf_new failed\0" as *const u8 as *const libc::c_char,
                __progname,
            );
        }
        r = sshbuf_put_u32(resp, 3 as libc::c_int as u_int32_t);
        if r != 0 as libc::c_int {
            sshfatal(
                b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"process_load_resident\0",
                ))
                .as_ptr(),
                247 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                ssh_err(r),
                b"%s: compose\0" as *const u8 as *const libc::c_char,
                __progname,
            );
        }
        i = 0 as libc::c_int as size_t;
        while i < nsrks {
            sshlog(
                b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"process_load_resident\0",
                ))
                .as_ptr(),
                252 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"key %zu %s %s uidlen %zu\0" as *const u8 as *const libc::c_char,
                i,
                sshkey_type((**srks.offset(i as isize)).key),
                (*(**srks.offset(i as isize)).key).sk_application,
                (**srks.offset(i as isize)).user_id_len,
            );
            sshbuf_reset(kbuf);
            r = sshkey_private_serialize((**srks.offset(i as isize)).key, kbuf);
            if r != 0 as libc::c_int {
                sshfatal(
                    b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"process_load_resident\0",
                    ))
                    .as_ptr(),
                    255 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"%s: encode key\0" as *const u8 as *const libc::c_char,
                    __progname,
                );
            }
            r = sshbuf_put_stringb(resp, kbuf);
            if r != 0 as libc::c_int
                || {
                    r = sshbuf_put_cstring(resp, b"\0" as *const u8 as *const libc::c_char);
                    r != 0 as libc::c_int
                }
                || {
                    r = sshbuf_put_string(
                        resp,
                        (**srks.offset(i as isize)).user_id as *const libc::c_void,
                        (**srks.offset(i as isize)).user_id_len,
                    );
                    r != 0 as libc::c_int
                }
            {
                sshfatal(
                    b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                        b"process_load_resident\0",
                    ))
                    .as_ptr(),
                    260 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_FATAL,
                    ssh_err(r),
                    b"%s: compose key\0" as *const u8 as *const libc::c_char,
                    __progname,
                );
            }
            i = i.wrapping_add(1);
            i;
        }
    }
    sshsk_free_resident_keys(srks, nsrks);
    sshbuf_free(kbuf);
    free(provider as *mut libc::c_void);
    free(device as *mut libc::c_void);
    if !pin.is_null() {
        freezero(pin as *mut libc::c_void, strlen(pin));
    }
    return resp;
}
unsafe fn main_0(mut argc: libc::c_int, mut argv: *mut *mut libc::c_char) -> libc::c_int {
    let mut log_facility: SyslogFacility = SYSLOG_FACILITY_AUTH;
    let mut log_level: LogLevel = SYSLOG_LEVEL_ERROR;
    let mut req: *mut sshbuf = 0 as *mut sshbuf;
    let mut resp: *mut sshbuf = 0 as *mut sshbuf;
    let mut in_0: libc::c_int = 0;
    let mut out: libc::c_int = 0;
    let mut ch: libc::c_int = 0;
    let mut r: libc::c_int = 0;
    let mut vflag: libc::c_int = 0 as libc::c_int;
    let mut rtype: u_int = 0;
    let mut ll: u_int = 0 as libc::c_int as u_int;
    let mut version: uint8_t = 0;
    let mut log_stderr: uint8_t = 0 as libc::c_int as uint8_t;
    sanitise_stdfd();
    log_init(
        __progname,
        log_level,
        log_facility,
        log_stderr as libc::c_int,
    );
    loop {
        ch = BSDgetopt(argc, argv, b"v\0" as *const u8 as *const libc::c_char);
        if !(ch != -(1 as libc::c_int)) {
            break;
        }
        match ch {
            118 => {
                vflag = 1 as libc::c_int;
                if log_level as libc::c_int == SYSLOG_LEVEL_ERROR as libc::c_int {
                    log_level = SYSLOG_LEVEL_DEBUG1;
                } else if (log_level as libc::c_int) < SYSLOG_LEVEL_DEBUG3 as libc::c_int {
                    log_level += 1;
                    log_level;
                }
            }
            _ => {
                fprintf(
                    stderr,
                    b"usage: %s [-v]\n\0" as *const u8 as *const libc::c_char,
                    __progname,
                );
                exit(1 as libc::c_int);
            }
        }
    }
    log_init(__progname, log_level, log_facility, vflag);
    closefrom(2 as libc::c_int + 1 as libc::c_int);
    in_0 = dup(0 as libc::c_int);
    if in_0 == -(1 as libc::c_int) || {
        out = dup(1 as libc::c_int);
        out == -(1 as libc::c_int)
    } {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            308 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: dup: %s\0" as *const u8 as *const libc::c_char,
            __progname,
            strerror(*__errno_location()),
        );
    }
    close(0 as libc::c_int);
    close(1 as libc::c_int);
    sanitise_stdfd();
    req = sshbuf_new();
    if req.is_null() {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            314 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"%s: sshbuf_new failed\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if ssh_msg_recv(in_0, req) < 0 as libc::c_int {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            316 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ssh_msg_recv failed\0" as *const u8 as *const libc::c_char,
        );
    }
    close(in_0);
    sshlog(
        b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
        318 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"received message len %zu\0" as *const u8 as *const libc::c_char,
        sshbuf_len(req),
    );
    r = sshbuf_get_u8(req, &mut version);
    if r != 0 as libc::c_int {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            321 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"%s: parse version\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if version as libc::c_int != 5 as libc::c_int {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            324 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"unsupported version: received %d, expected %d\0" as *const u8 as *const libc::c_char,
            version as libc::c_int,
            5 as libc::c_int,
        );
    }
    r = sshbuf_get_u32(req, &mut rtype);
    if r != 0 as libc::c_int
        || {
            r = sshbuf_get_u8(req, &mut log_stderr);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_get_u32(req, &mut ll);
            r != 0 as libc::c_int
        }
    {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            330 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            ssh_err(r),
            b"%s: parse\0" as *const u8 as *const libc::c_char,
            __progname,
        );
    }
    if vflag == 0 && !(log_level_name(ll as LogLevel)).is_null() {
        log_init(
            __progname,
            ll as LogLevel,
            log_facility,
            log_stderr as libc::c_int,
        );
    }
    match rtype {
        1 => {
            resp = process_sign(req);
        }
        2 => {
            resp = process_enroll(req);
        }
        3 => {
            resp = process_load_resident(req);
        }
        _ => {
            sshfatal(
                b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
                346 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_FATAL,
                0 as *const libc::c_char,
                b"%s: unsupported request type %u\0" as *const u8 as *const libc::c_char,
                __progname,
                rtype,
            );
        }
    }
    sshbuf_free(req);
    sshlog(
        b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
        349 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"reply len %zu\0" as *const u8 as *const libc::c_char,
        sshbuf_len(resp),
    );
    if ssh_msg_send(out, 5 as libc::c_int as u_char, resp) == -(1 as libc::c_int) {
        sshfatal(
            b"ssh-sk-helper.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 5], &[libc::c_char; 5]>(b"main\0")).as_ptr(),
            352 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"ssh_msg_send failed\0" as *const u8 as *const libc::c_char,
        );
    }
    sshbuf_free(resp);
    close(out);
    return 0 as libc::c_int;
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
