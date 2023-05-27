use ::libc;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    pub type sshbuf;
    pub type dsa_st;
    pub type rsa_st;
    pub type ec_key_st;
    pub type bitmap;
    fn __errno_location() -> *mut libc::c_int;
    fn fprintf(_: *mut libc::FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn fputc(__c: libc::c_int, __stream: *mut libc::FILE) -> libc::c_int;
    fn recallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn memcmp(_: *const libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> libc::c_int;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn time(__timer: *mut time_t) -> time_t;
    fn strftime(
        __s: *mut libc::c_char,
        __maxsize: size_t,
        __format: *const libc::c_char,
        __tp: *const tm,
    ) -> size_t;
    fn localtime(__timer: *const time_t) -> *mut tm;
    fn sshbuf_load_file(_: *const libc::c_char, _: *mut *mut sshbuf) -> libc::c_int;
    fn sshbuf_get_bignum2_bytes_direct(
        buf: *mut sshbuf,
        valp: *mut *const u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshbuf_put_bignum2_bytes(
        buf: *mut sshbuf,
        v: *const libc::c_void,
        len: size_t,
    ) -> libc::c_int;
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
    fn sshbuf_put_u64(buf: *mut sshbuf, val: u_int64_t) -> libc::c_int;
    fn sshbuf_get_u8(buf: *mut sshbuf, valp: *mut u_char) -> libc::c_int;
    fn sshbuf_get_u32(buf: *mut sshbuf, valp: *mut u_int32_t) -> libc::c_int;
    fn sshbuf_get_u64(buf: *mut sshbuf, valp: *mut u_int64_t) -> libc::c_int;
    fn sshbuf_put(buf: *mut sshbuf, v: *const libc::c_void, len: size_t) -> libc::c_int;
    fn sshbuf_consume(buf: *mut sshbuf, len: size_t) -> libc::c_int;
    fn sshbuf_ptr(buf: *const sshbuf) -> *const u_char;
    fn sshbuf_len(buf: *const sshbuf) -> size_t;
    fn sshbuf_reset(buf: *mut sshbuf);
    fn sshbuf_free(buf: *mut sshbuf);
    fn sshbuf_froms(buf: *mut sshbuf, bufp: *mut *mut sshbuf) -> libc::c_int;
    fn sshbuf_fromb(buf: *mut sshbuf) -> *mut sshbuf;
    fn sshbuf_new() -> *mut sshbuf;
    fn ssh_err(n: libc::c_int) -> *const libc::c_char;
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_equal(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_fingerprint(_: *const sshkey, _: libc::c_int, _: sshkey_fp_rep) -> *mut libc::c_char;
    fn sshkey_fingerprint_raw(
        k: *const sshkey,
        _: libc::c_int,
        retp: *mut *mut u_char,
        lenp: *mut size_t,
    ) -> libc::c_int;
    fn sshkey_type(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_from_private(_: *const sshkey, _: *mut *mut sshkey) -> libc::c_int;
    fn sshkey_is_cert(_: *const sshkey) -> libc::c_int;
    fn sshkey_drop_cert(_: *mut sshkey) -> libc::c_int;
    fn sshkey_ssh_name(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_from_blob(_: *const u_char, _: size_t, _: *mut *mut sshkey) -> libc::c_int;
    fn sshkey_to_blob(_: *const sshkey, _: *mut *mut u_char, _: *mut size_t) -> libc::c_int;
    fn sshkey_puts(_: *const sshkey, _: *mut sshbuf) -> libc::c_int;
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
    fn tohex(_: *const libc::c_void, _: size_t) -> *mut libc::c_char;

    fn bitmap_new() -> *mut bitmap;
    fn bitmap_free(b: *mut bitmap);
    fn bitmap_test_bit(b: *mut bitmap, n: u_int) -> libc::c_int;
    fn bitmap_set_bit(b: *mut bitmap, n: u_int) -> libc::c_int;
    fn bitmap_nbits(b: *mut bitmap) -> size_t;
    fn bitmap_nbytes(b: *mut bitmap) -> size_t;
    fn bitmap_to_string(b: *mut bitmap, p: *mut libc::c_void, l: size_t) -> libc::c_int;
    fn bitmap_from_string(b: *mut bitmap, p: *const libc::c_void, l: size_t) -> libc::c_int;
    fn asmprintf(
        _: *mut *mut libc::c_char,
        _: size_t,
        _: *mut libc::c_int,
        _: *const libc::c_char,
        _: ...
    ) -> libc::c_int;
}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type time_t = __time_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;
pub type uint32_t = __uint32_t;
pub type uint8_t = __uint8_t;

pub type _IO_lock_t = ();

#[derive(Copy, Clone)]
#[repr(C)]
pub struct tm {
    pub tm_sec: libc::c_int,
    pub tm_min: libc::c_int,
    pub tm_hour: libc::c_int,
    pub tm_mday: libc::c_int,
    pub tm_mon: libc::c_int,
    pub tm_year: libc::c_int,
    pub tm_wday: libc::c_int,
    pub tm_yday: libc::c_int,
    pub tm_isdst: libc::c_int,
    pub tm_gmtoff: libc::c_long,
    pub tm_zone: *const libc::c_char,
}
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type EC_KEY = ec_key_st;
pub type sshkey_fp_rep = libc::c_uint;
pub const SSH_FP_RANDOMART: sshkey_fp_rep = 4;
pub const SSH_FP_BUBBLEBABBLE: sshkey_fp_rep = 3;
pub const SSH_FP_BASE64: sshkey_fp_rep = 2;
pub const SSH_FP_HEX: sshkey_fp_rep = 1;
pub const SSH_FP_DEFAULT: sshkey_fp_rep = 0;
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
pub struct sshkey_sig_details {
    pub sk_counter: uint32_t,
    pub sk_flags: uint8_t,
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
pub struct ssh_krl {
    pub krl_version: u_int64_t,
    pub generated_date: u_int64_t,
    pub flags: u_int64_t,
    pub comment: *mut libc::c_char,
    pub revoked_keys: revoked_blob_tree,
    pub revoked_sha1s: revoked_blob_tree,
    pub revoked_sha256s: revoked_blob_tree,
    pub revoked_certs: revoked_certs_list,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct revoked_certs_list {
    pub tqh_first: *mut revoked_certs,
    pub tqh_last: *mut *mut revoked_certs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct revoked_certs {
    pub ca_key: *mut sshkey,
    pub revoked_serials: revoked_serial_tree,
    pub revoked_key_ids: revoked_key_id_tree,
    pub entry: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub tqe_next: *mut revoked_certs,
    pub tqe_prev: *mut *mut revoked_certs,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct revoked_key_id_tree {
    pub rbh_root: *mut revoked_key_id,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct revoked_key_id {
    pub key_id: *mut libc::c_char,
    pub tree_entry: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub rbe_left: *mut revoked_key_id,
    pub rbe_right: *mut revoked_key_id,
    pub rbe_parent: *mut revoked_key_id,
    pub rbe_color: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct revoked_serial_tree {
    pub rbh_root: *mut revoked_serial,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct revoked_serial {
    pub lo: u_int64_t,
    pub hi: u_int64_t,
    pub tree_entry: C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub rbe_left: *mut revoked_serial,
    pub rbe_right: *mut revoked_serial,
    pub rbe_parent: *mut revoked_serial,
    pub rbe_color: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct revoked_blob_tree {
    pub rbh_root: *mut revoked_blob,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct revoked_blob {
    pub blob: *mut u_char,
    pub len: size_t,
    pub tree_entry: C2RustUnnamed_2,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub rbe_left: *mut revoked_blob,
    pub rbe_right: *mut revoked_blob,
    pub rbe_parent: *mut revoked_blob,
    pub rbe_color: libc::c_int,
}
unsafe extern "C" fn revoked_serial_tree_RB_INSERT(
    mut head: *mut revoked_serial_tree,
    mut elm: *mut revoked_serial,
) -> *mut revoked_serial {
    let mut tmp: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut parent: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut comp: libc::c_int = 0 as libc::c_int;
    tmp = (*head).rbh_root;
    while !tmp.is_null() {
        parent = tmp;
        comp = serial_cmp(elm, parent);
        if comp < 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_left;
        } else if comp > 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_right;
        } else {
            return tmp;
        }
    }
    (*elm).tree_entry.rbe_parent = parent;
    (*elm).tree_entry.rbe_right = 0 as *mut revoked_serial;
    (*elm).tree_entry.rbe_left = (*elm).tree_entry.rbe_right;
    (*elm).tree_entry.rbe_color = 1 as libc::c_int;
    if !parent.is_null() {
        if comp < 0 as libc::c_int {
            (*parent).tree_entry.rbe_left = elm;
        } else {
            (*parent).tree_entry.rbe_right = elm;
        }
    } else {
        (*head).rbh_root = elm;
    }
    revoked_serial_tree_RB_INSERT_COLOR(head, elm);
    return 0 as *mut revoked_serial;
}
unsafe extern "C" fn revoked_serial_tree_RB_NEXT(
    mut elm: *mut revoked_serial,
) -> *mut revoked_serial {
    if !((*elm).tree_entry.rbe_right).is_null() {
        elm = (*elm).tree_entry.rbe_right;
        while !((*elm).tree_entry.rbe_left).is_null() {
            elm = (*elm).tree_entry.rbe_left;
        }
    } else if !((*elm).tree_entry.rbe_parent).is_null()
        && elm == (*(*elm).tree_entry.rbe_parent).tree_entry.rbe_left
    {
        elm = (*elm).tree_entry.rbe_parent;
    } else {
        while !((*elm).tree_entry.rbe_parent).is_null()
            && elm == (*(*elm).tree_entry.rbe_parent).tree_entry.rbe_right
        {
            elm = (*elm).tree_entry.rbe_parent;
        }
        elm = (*elm).tree_entry.rbe_parent;
    }
    return elm;
}
unsafe extern "C" fn revoked_serial_tree_RB_REMOVE(
    mut head: *mut revoked_serial_tree,
    mut elm: *mut revoked_serial,
) -> *mut revoked_serial {
    let mut current_block: u64;
    let mut child: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut parent: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut old: *mut revoked_serial = elm;
    let mut color: libc::c_int = 0;
    if ((*elm).tree_entry.rbe_left).is_null() {
        child = (*elm).tree_entry.rbe_right;
        current_block = 7245201122033322888;
    } else if ((*elm).tree_entry.rbe_right).is_null() {
        child = (*elm).tree_entry.rbe_left;
        current_block = 7245201122033322888;
    } else {
        let mut left: *mut revoked_serial = 0 as *mut revoked_serial;
        elm = (*elm).tree_entry.rbe_right;
        loop {
            left = (*elm).tree_entry.rbe_left;
            if left.is_null() {
                break;
            }
            elm = left;
        }
        child = (*elm).tree_entry.rbe_right;
        parent = (*elm).tree_entry.rbe_parent;
        color = (*elm).tree_entry.rbe_color;
        if !child.is_null() {
            (*child).tree_entry.rbe_parent = parent;
        }
        if !parent.is_null() {
            if (*parent).tree_entry.rbe_left == elm {
                (*parent).tree_entry.rbe_left = child;
            } else {
                (*parent).tree_entry.rbe_right = child;
            }
        } else {
            (*head).rbh_root = child;
        }
        if (*elm).tree_entry.rbe_parent == old {
            parent = elm;
        }
        (*elm).tree_entry = (*old).tree_entry;
        if !((*old).tree_entry.rbe_parent).is_null() {
            if (*(*old).tree_entry.rbe_parent).tree_entry.rbe_left == old {
                (*(*old).tree_entry.rbe_parent).tree_entry.rbe_left = elm;
            } else {
                (*(*old).tree_entry.rbe_parent).tree_entry.rbe_right = elm;
            }
        } else {
            (*head).rbh_root = elm;
        }
        (*(*old).tree_entry.rbe_left).tree_entry.rbe_parent = elm;
        if !((*old).tree_entry.rbe_right).is_null() {
            (*(*old).tree_entry.rbe_right).tree_entry.rbe_parent = elm;
        }
        if !parent.is_null() {
            left = parent;
            loop {
                left = (*left).tree_entry.rbe_parent;
                if left.is_null() {
                    break;
                }
            }
        }
        current_block = 7575662447508998237;
    }
    match current_block {
        7245201122033322888 => {
            parent = (*elm).tree_entry.rbe_parent;
            color = (*elm).tree_entry.rbe_color;
            if !child.is_null() {
                (*child).tree_entry.rbe_parent = parent;
            }
            if !parent.is_null() {
                if (*parent).tree_entry.rbe_left == elm {
                    (*parent).tree_entry.rbe_left = child;
                } else {
                    (*parent).tree_entry.rbe_right = child;
                }
            } else {
                (*head).rbh_root = child;
            }
        }
        _ => {}
    }
    if color == 0 as libc::c_int {
        revoked_serial_tree_RB_REMOVE_COLOR(head, parent, child);
    }
    return old;
}
unsafe extern "C" fn revoked_serial_tree_RB_FIND(
    mut head: *mut revoked_serial_tree,
    mut elm: *mut revoked_serial,
) -> *mut revoked_serial {
    let mut tmp: *mut revoked_serial = (*head).rbh_root;
    let mut comp: libc::c_int = 0;
    while !tmp.is_null() {
        comp = serial_cmp(elm, tmp);
        if comp < 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_left;
        } else if comp > 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_right;
        } else {
            return tmp;
        }
    }
    return 0 as *mut revoked_serial;
}
unsafe extern "C" fn revoked_serial_tree_RB_REMOVE_COLOR(
    mut head: *mut revoked_serial_tree,
    mut parent: *mut revoked_serial,
    mut elm: *mut revoked_serial,
) {
    let mut tmp: *mut revoked_serial = 0 as *mut revoked_serial;
    while (elm.is_null() || (*elm).tree_entry.rbe_color == 0 as libc::c_int)
        && elm != (*head).rbh_root
    {
        if (*parent).tree_entry.rbe_left == elm {
            tmp = (*parent).tree_entry.rbe_right;
            if (*tmp).tree_entry.rbe_color == 1 as libc::c_int {
                (*tmp).tree_entry.rbe_color = 0 as libc::c_int;
                (*parent).tree_entry.rbe_color = 1 as libc::c_int;
                tmp = (*parent).tree_entry.rbe_right;
                (*parent).tree_entry.rbe_right = (*tmp).tree_entry.rbe_left;
                if !((*parent).tree_entry.rbe_right).is_null() {
                    (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_parent = parent;
                }
                (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_left = parent;
                (*parent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
                tmp = (*parent).tree_entry.rbe_right;
            }
            if (((*tmp).tree_entry.rbe_left).is_null()
                || (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_color == 0 as libc::c_int)
                && (((*tmp).tree_entry.rbe_right).is_null()
                    || (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_color == 0 as libc::c_int)
            {
                (*tmp).tree_entry.rbe_color = 1 as libc::c_int;
                elm = parent;
                parent = (*elm).tree_entry.rbe_parent;
            } else {
                if ((*tmp).tree_entry.rbe_right).is_null()
                    || (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_color == 0 as libc::c_int
                {
                    let mut oleft: *mut revoked_serial = 0 as *mut revoked_serial;
                    oleft = (*tmp).tree_entry.rbe_left;
                    if !oleft.is_null() {
                        (*oleft).tree_entry.rbe_color = 0 as libc::c_int;
                    }
                    (*tmp).tree_entry.rbe_color = 1 as libc::c_int;
                    oleft = (*tmp).tree_entry.rbe_left;
                    (*tmp).tree_entry.rbe_left = (*oleft).tree_entry.rbe_right;
                    if !((*tmp).tree_entry.rbe_left).is_null() {
                        (*(*oleft).tree_entry.rbe_right).tree_entry.rbe_parent = tmp;
                    }
                    (*oleft).tree_entry.rbe_parent = (*tmp).tree_entry.rbe_parent;
                    if !((*oleft).tree_entry.rbe_parent).is_null() {
                        if tmp == (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_left {
                            (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_left = oleft;
                        } else {
                            (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_right = oleft;
                        }
                    } else {
                        (*head).rbh_root = oleft;
                    }
                    (*oleft).tree_entry.rbe_right = tmp;
                    (*tmp).tree_entry.rbe_parent = oleft;
                    !((*oleft).tree_entry.rbe_parent).is_null();
                    tmp = (*parent).tree_entry.rbe_right;
                }
                (*tmp).tree_entry.rbe_color = (*parent).tree_entry.rbe_color;
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                if !((*tmp).tree_entry.rbe_right).is_null() {
                    (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_color = 0 as libc::c_int;
                }
                tmp = (*parent).tree_entry.rbe_right;
                (*parent).tree_entry.rbe_right = (*tmp).tree_entry.rbe_left;
                if !((*parent).tree_entry.rbe_right).is_null() {
                    (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_parent = parent;
                }
                (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_left = parent;
                (*parent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
                elm = (*head).rbh_root;
                break;
            }
        } else {
            tmp = (*parent).tree_entry.rbe_left;
            if (*tmp).tree_entry.rbe_color == 1 as libc::c_int {
                (*tmp).tree_entry.rbe_color = 0 as libc::c_int;
                (*parent).tree_entry.rbe_color = 1 as libc::c_int;
                tmp = (*parent).tree_entry.rbe_left;
                (*parent).tree_entry.rbe_left = (*tmp).tree_entry.rbe_right;
                if !((*parent).tree_entry.rbe_left).is_null() {
                    (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_parent = parent;
                }
                (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_right = parent;
                (*parent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
                tmp = (*parent).tree_entry.rbe_left;
            }
            if (((*tmp).tree_entry.rbe_left).is_null()
                || (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_color == 0 as libc::c_int)
                && (((*tmp).tree_entry.rbe_right).is_null()
                    || (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_color == 0 as libc::c_int)
            {
                (*tmp).tree_entry.rbe_color = 1 as libc::c_int;
                elm = parent;
                parent = (*elm).tree_entry.rbe_parent;
            } else {
                if ((*tmp).tree_entry.rbe_left).is_null()
                    || (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_color == 0 as libc::c_int
                {
                    let mut oright: *mut revoked_serial = 0 as *mut revoked_serial;
                    oright = (*tmp).tree_entry.rbe_right;
                    if !oright.is_null() {
                        (*oright).tree_entry.rbe_color = 0 as libc::c_int;
                    }
                    (*tmp).tree_entry.rbe_color = 1 as libc::c_int;
                    oright = (*tmp).tree_entry.rbe_right;
                    (*tmp).tree_entry.rbe_right = (*oright).tree_entry.rbe_left;
                    if !((*tmp).tree_entry.rbe_right).is_null() {
                        (*(*oright).tree_entry.rbe_left).tree_entry.rbe_parent = tmp;
                    }
                    (*oright).tree_entry.rbe_parent = (*tmp).tree_entry.rbe_parent;
                    if !((*oright).tree_entry.rbe_parent).is_null() {
                        if tmp == (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_left {
                            (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_left = oright;
                        } else {
                            (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_right = oright;
                        }
                    } else {
                        (*head).rbh_root = oright;
                    }
                    (*oright).tree_entry.rbe_left = tmp;
                    (*tmp).tree_entry.rbe_parent = oright;
                    !((*oright).tree_entry.rbe_parent).is_null();
                    tmp = (*parent).tree_entry.rbe_left;
                }
                (*tmp).tree_entry.rbe_color = (*parent).tree_entry.rbe_color;
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                if !((*tmp).tree_entry.rbe_left).is_null() {
                    (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_color = 0 as libc::c_int;
                }
                tmp = (*parent).tree_entry.rbe_left;
                (*parent).tree_entry.rbe_left = (*tmp).tree_entry.rbe_right;
                if !((*parent).tree_entry.rbe_left).is_null() {
                    (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_parent = parent;
                }
                (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_right = parent;
                (*parent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
                elm = (*head).rbh_root;
                break;
            }
        }
    }
    if !elm.is_null() {
        (*elm).tree_entry.rbe_color = 0 as libc::c_int;
    }
}
unsafe extern "C" fn revoked_serial_tree_RB_MINMAX(
    mut head: *mut revoked_serial_tree,
    mut val: libc::c_int,
) -> *mut revoked_serial {
    let mut tmp: *mut revoked_serial = (*head).rbh_root;
    let mut parent: *mut revoked_serial = 0 as *mut revoked_serial;
    while !tmp.is_null() {
        parent = tmp;
        if val < 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_left;
        } else {
            tmp = (*tmp).tree_entry.rbe_right;
        }
    }
    return parent;
}
unsafe extern "C" fn revoked_serial_tree_RB_NFIND(
    mut head: *mut revoked_serial_tree,
    mut elm: *mut revoked_serial,
) -> *mut revoked_serial {
    let mut tmp: *mut revoked_serial = (*head).rbh_root;
    let mut res: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut comp: libc::c_int = 0;
    while !tmp.is_null() {
        comp = serial_cmp(elm, tmp);
        if comp < 0 as libc::c_int {
            res = tmp;
            tmp = (*tmp).tree_entry.rbe_left;
        } else if comp > 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_right;
        } else {
            return tmp;
        }
    }
    return res;
}
unsafe extern "C" fn revoked_serial_tree_RB_INSERT_COLOR(
    mut head: *mut revoked_serial_tree,
    mut elm: *mut revoked_serial,
) {
    let mut parent: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut gparent: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut tmp: *mut revoked_serial = 0 as *mut revoked_serial;
    loop {
        parent = (*elm).tree_entry.rbe_parent;
        if !(!parent.is_null() && (*parent).tree_entry.rbe_color == 1 as libc::c_int) {
            break;
        }
        gparent = (*parent).tree_entry.rbe_parent;
        if parent == (*gparent).tree_entry.rbe_left {
            tmp = (*gparent).tree_entry.rbe_right;
            if !tmp.is_null() && (*tmp).tree_entry.rbe_color == 1 as libc::c_int {
                (*tmp).tree_entry.rbe_color = 0 as libc::c_int;
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                (*gparent).tree_entry.rbe_color = 1 as libc::c_int;
                elm = gparent;
            } else {
                if (*parent).tree_entry.rbe_right == elm {
                    tmp = (*parent).tree_entry.rbe_right;
                    (*parent).tree_entry.rbe_right = (*tmp).tree_entry.rbe_left;
                    if !((*parent).tree_entry.rbe_right).is_null() {
                        (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_parent = parent;
                    }
                    (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                    if !((*tmp).tree_entry.rbe_parent).is_null() {
                        if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                            (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                        } else {
                            (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                        }
                    } else {
                        (*head).rbh_root = tmp;
                    }
                    (*tmp).tree_entry.rbe_left = parent;
                    (*parent).tree_entry.rbe_parent = tmp;
                    !((*tmp).tree_entry.rbe_parent).is_null();
                    tmp = parent;
                    parent = elm;
                    elm = tmp;
                }
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                (*gparent).tree_entry.rbe_color = 1 as libc::c_int;
                tmp = (*gparent).tree_entry.rbe_left;
                (*gparent).tree_entry.rbe_left = (*tmp).tree_entry.rbe_right;
                if !((*gparent).tree_entry.rbe_left).is_null() {
                    (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_parent = gparent;
                }
                (*tmp).tree_entry.rbe_parent = (*gparent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if gparent == (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_right = gparent;
                (*gparent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
            }
        } else {
            tmp = (*gparent).tree_entry.rbe_left;
            if !tmp.is_null() && (*tmp).tree_entry.rbe_color == 1 as libc::c_int {
                (*tmp).tree_entry.rbe_color = 0 as libc::c_int;
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                (*gparent).tree_entry.rbe_color = 1 as libc::c_int;
                elm = gparent;
            } else {
                if (*parent).tree_entry.rbe_left == elm {
                    tmp = (*parent).tree_entry.rbe_left;
                    (*parent).tree_entry.rbe_left = (*tmp).tree_entry.rbe_right;
                    if !((*parent).tree_entry.rbe_left).is_null() {
                        (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_parent = parent;
                    }
                    (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                    if !((*tmp).tree_entry.rbe_parent).is_null() {
                        if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                            (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                        } else {
                            (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                        }
                    } else {
                        (*head).rbh_root = tmp;
                    }
                    (*tmp).tree_entry.rbe_right = parent;
                    (*parent).tree_entry.rbe_parent = tmp;
                    !((*tmp).tree_entry.rbe_parent).is_null();
                    tmp = parent;
                    parent = elm;
                    elm = tmp;
                }
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                (*gparent).tree_entry.rbe_color = 1 as libc::c_int;
                tmp = (*gparent).tree_entry.rbe_right;
                (*gparent).tree_entry.rbe_right = (*tmp).tree_entry.rbe_left;
                if !((*gparent).tree_entry.rbe_right).is_null() {
                    (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_parent = gparent;
                }
                (*tmp).tree_entry.rbe_parent = (*gparent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if gparent == (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_left = gparent;
                (*gparent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
            }
        }
    }
    (*(*head).rbh_root).tree_entry.rbe_color = 0 as libc::c_int;
}
unsafe extern "C" fn revoked_serial_tree_RB_PREV(
    mut elm: *mut revoked_serial,
) -> *mut revoked_serial {
    if !((*elm).tree_entry.rbe_left).is_null() {
        elm = (*elm).tree_entry.rbe_left;
        while !((*elm).tree_entry.rbe_right).is_null() {
            elm = (*elm).tree_entry.rbe_right;
        }
    } else if !((*elm).tree_entry.rbe_parent).is_null()
        && elm == (*(*elm).tree_entry.rbe_parent).tree_entry.rbe_right
    {
        elm = (*elm).tree_entry.rbe_parent;
    } else {
        while !((*elm).tree_entry.rbe_parent).is_null()
            && elm == (*(*elm).tree_entry.rbe_parent).tree_entry.rbe_left
        {
            elm = (*elm).tree_entry.rbe_parent;
        }
        elm = (*elm).tree_entry.rbe_parent;
    }
    return elm;
}
unsafe extern "C" fn revoked_key_id_tree_RB_INSERT(
    mut head: *mut revoked_key_id_tree,
    mut elm: *mut revoked_key_id,
) -> *mut revoked_key_id {
    let mut tmp: *mut revoked_key_id = 0 as *mut revoked_key_id;
    let mut parent: *mut revoked_key_id = 0 as *mut revoked_key_id;
    let mut comp: libc::c_int = 0 as libc::c_int;
    tmp = (*head).rbh_root;
    while !tmp.is_null() {
        parent = tmp;
        comp = key_id_cmp(elm, parent);
        if comp < 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_left;
        } else if comp > 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_right;
        } else {
            return tmp;
        }
    }
    (*elm).tree_entry.rbe_parent = parent;
    (*elm).tree_entry.rbe_right = 0 as *mut revoked_key_id;
    (*elm).tree_entry.rbe_left = (*elm).tree_entry.rbe_right;
    (*elm).tree_entry.rbe_color = 1 as libc::c_int;
    if !parent.is_null() {
        if comp < 0 as libc::c_int {
            (*parent).tree_entry.rbe_left = elm;
        } else {
            (*parent).tree_entry.rbe_right = elm;
        }
    } else {
        (*head).rbh_root = elm;
    }
    revoked_key_id_tree_RB_INSERT_COLOR(head, elm);
    return 0 as *mut revoked_key_id;
}
unsafe extern "C" fn revoked_key_id_tree_RB_FIND(
    mut head: *mut revoked_key_id_tree,
    mut elm: *mut revoked_key_id,
) -> *mut revoked_key_id {
    let mut tmp: *mut revoked_key_id = (*head).rbh_root;
    let mut comp: libc::c_int = 0;
    while !tmp.is_null() {
        comp = key_id_cmp(elm, tmp);
        if comp < 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_left;
        } else if comp > 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_right;
        } else {
            return tmp;
        }
    }
    return 0 as *mut revoked_key_id;
}
unsafe extern "C" fn revoked_key_id_tree_RB_INSERT_COLOR(
    mut head: *mut revoked_key_id_tree,
    mut elm: *mut revoked_key_id,
) {
    let mut parent: *mut revoked_key_id = 0 as *mut revoked_key_id;
    let mut gparent: *mut revoked_key_id = 0 as *mut revoked_key_id;
    let mut tmp: *mut revoked_key_id = 0 as *mut revoked_key_id;
    loop {
        parent = (*elm).tree_entry.rbe_parent;
        if !(!parent.is_null() && (*parent).tree_entry.rbe_color == 1 as libc::c_int) {
            break;
        }
        gparent = (*parent).tree_entry.rbe_parent;
        if parent == (*gparent).tree_entry.rbe_left {
            tmp = (*gparent).tree_entry.rbe_right;
            if !tmp.is_null() && (*tmp).tree_entry.rbe_color == 1 as libc::c_int {
                (*tmp).tree_entry.rbe_color = 0 as libc::c_int;
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                (*gparent).tree_entry.rbe_color = 1 as libc::c_int;
                elm = gparent;
            } else {
                if (*parent).tree_entry.rbe_right == elm {
                    tmp = (*parent).tree_entry.rbe_right;
                    (*parent).tree_entry.rbe_right = (*tmp).tree_entry.rbe_left;
                    if !((*parent).tree_entry.rbe_right).is_null() {
                        (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_parent = parent;
                    }
                    (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                    if !((*tmp).tree_entry.rbe_parent).is_null() {
                        if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                            (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                        } else {
                            (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                        }
                    } else {
                        (*head).rbh_root = tmp;
                    }
                    (*tmp).tree_entry.rbe_left = parent;
                    (*parent).tree_entry.rbe_parent = tmp;
                    !((*tmp).tree_entry.rbe_parent).is_null();
                    tmp = parent;
                    parent = elm;
                    elm = tmp;
                }
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                (*gparent).tree_entry.rbe_color = 1 as libc::c_int;
                tmp = (*gparent).tree_entry.rbe_left;
                (*gparent).tree_entry.rbe_left = (*tmp).tree_entry.rbe_right;
                if !((*gparent).tree_entry.rbe_left).is_null() {
                    (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_parent = gparent;
                }
                (*tmp).tree_entry.rbe_parent = (*gparent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if gparent == (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_right = gparent;
                (*gparent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
            }
        } else {
            tmp = (*gparent).tree_entry.rbe_left;
            if !tmp.is_null() && (*tmp).tree_entry.rbe_color == 1 as libc::c_int {
                (*tmp).tree_entry.rbe_color = 0 as libc::c_int;
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                (*gparent).tree_entry.rbe_color = 1 as libc::c_int;
                elm = gparent;
            } else {
                if (*parent).tree_entry.rbe_left == elm {
                    tmp = (*parent).tree_entry.rbe_left;
                    (*parent).tree_entry.rbe_left = (*tmp).tree_entry.rbe_right;
                    if !((*parent).tree_entry.rbe_left).is_null() {
                        (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_parent = parent;
                    }
                    (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                    if !((*tmp).tree_entry.rbe_parent).is_null() {
                        if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                            (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                        } else {
                            (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                        }
                    } else {
                        (*head).rbh_root = tmp;
                    }
                    (*tmp).tree_entry.rbe_right = parent;
                    (*parent).tree_entry.rbe_parent = tmp;
                    !((*tmp).tree_entry.rbe_parent).is_null();
                    tmp = parent;
                    parent = elm;
                    elm = tmp;
                }
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                (*gparent).tree_entry.rbe_color = 1 as libc::c_int;
                tmp = (*gparent).tree_entry.rbe_right;
                (*gparent).tree_entry.rbe_right = (*tmp).tree_entry.rbe_left;
                if !((*gparent).tree_entry.rbe_right).is_null() {
                    (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_parent = gparent;
                }
                (*tmp).tree_entry.rbe_parent = (*gparent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if gparent == (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_left = gparent;
                (*gparent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
            }
        }
    }
    (*(*head).rbh_root).tree_entry.rbe_color = 0 as libc::c_int;
}
unsafe extern "C" fn revoked_key_id_tree_RB_MINMAX(
    mut head: *mut revoked_key_id_tree,
    mut val: libc::c_int,
) -> *mut revoked_key_id {
    let mut tmp: *mut revoked_key_id = (*head).rbh_root;
    let mut parent: *mut revoked_key_id = 0 as *mut revoked_key_id;
    while !tmp.is_null() {
        parent = tmp;
        if val < 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_left;
        } else {
            tmp = (*tmp).tree_entry.rbe_right;
        }
    }
    return parent;
}
unsafe extern "C" fn revoked_key_id_tree_RB_NEXT(
    mut elm: *mut revoked_key_id,
) -> *mut revoked_key_id {
    if !((*elm).tree_entry.rbe_right).is_null() {
        elm = (*elm).tree_entry.rbe_right;
        while !((*elm).tree_entry.rbe_left).is_null() {
            elm = (*elm).tree_entry.rbe_left;
        }
    } else if !((*elm).tree_entry.rbe_parent).is_null()
        && elm == (*(*elm).tree_entry.rbe_parent).tree_entry.rbe_left
    {
        elm = (*elm).tree_entry.rbe_parent;
    } else {
        while !((*elm).tree_entry.rbe_parent).is_null()
            && elm == (*(*elm).tree_entry.rbe_parent).tree_entry.rbe_right
        {
            elm = (*elm).tree_entry.rbe_parent;
        }
        elm = (*elm).tree_entry.rbe_parent;
    }
    return elm;
}
unsafe extern "C" fn revoked_key_id_tree_RB_REMOVE_COLOR(
    mut head: *mut revoked_key_id_tree,
    mut parent: *mut revoked_key_id,
    mut elm: *mut revoked_key_id,
) {
    let mut tmp: *mut revoked_key_id = 0 as *mut revoked_key_id;
    while (elm.is_null() || (*elm).tree_entry.rbe_color == 0 as libc::c_int)
        && elm != (*head).rbh_root
    {
        if (*parent).tree_entry.rbe_left == elm {
            tmp = (*parent).tree_entry.rbe_right;
            if (*tmp).tree_entry.rbe_color == 1 as libc::c_int {
                (*tmp).tree_entry.rbe_color = 0 as libc::c_int;
                (*parent).tree_entry.rbe_color = 1 as libc::c_int;
                tmp = (*parent).tree_entry.rbe_right;
                (*parent).tree_entry.rbe_right = (*tmp).tree_entry.rbe_left;
                if !((*parent).tree_entry.rbe_right).is_null() {
                    (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_parent = parent;
                }
                (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_left = parent;
                (*parent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
                tmp = (*parent).tree_entry.rbe_right;
            }
            if (((*tmp).tree_entry.rbe_left).is_null()
                || (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_color == 0 as libc::c_int)
                && (((*tmp).tree_entry.rbe_right).is_null()
                    || (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_color == 0 as libc::c_int)
            {
                (*tmp).tree_entry.rbe_color = 1 as libc::c_int;
                elm = parent;
                parent = (*elm).tree_entry.rbe_parent;
            } else {
                if ((*tmp).tree_entry.rbe_right).is_null()
                    || (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_color == 0 as libc::c_int
                {
                    let mut oleft: *mut revoked_key_id = 0 as *mut revoked_key_id;
                    oleft = (*tmp).tree_entry.rbe_left;
                    if !oleft.is_null() {
                        (*oleft).tree_entry.rbe_color = 0 as libc::c_int;
                    }
                    (*tmp).tree_entry.rbe_color = 1 as libc::c_int;
                    oleft = (*tmp).tree_entry.rbe_left;
                    (*tmp).tree_entry.rbe_left = (*oleft).tree_entry.rbe_right;
                    if !((*tmp).tree_entry.rbe_left).is_null() {
                        (*(*oleft).tree_entry.rbe_right).tree_entry.rbe_parent = tmp;
                    }
                    (*oleft).tree_entry.rbe_parent = (*tmp).tree_entry.rbe_parent;
                    if !((*oleft).tree_entry.rbe_parent).is_null() {
                        if tmp == (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_left {
                            (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_left = oleft;
                        } else {
                            (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_right = oleft;
                        }
                    } else {
                        (*head).rbh_root = oleft;
                    }
                    (*oleft).tree_entry.rbe_right = tmp;
                    (*tmp).tree_entry.rbe_parent = oleft;
                    !((*oleft).tree_entry.rbe_parent).is_null();
                    tmp = (*parent).tree_entry.rbe_right;
                }
                (*tmp).tree_entry.rbe_color = (*parent).tree_entry.rbe_color;
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                if !((*tmp).tree_entry.rbe_right).is_null() {
                    (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_color = 0 as libc::c_int;
                }
                tmp = (*parent).tree_entry.rbe_right;
                (*parent).tree_entry.rbe_right = (*tmp).tree_entry.rbe_left;
                if !((*parent).tree_entry.rbe_right).is_null() {
                    (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_parent = parent;
                }
                (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_left = parent;
                (*parent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
                elm = (*head).rbh_root;
                break;
            }
        } else {
            tmp = (*parent).tree_entry.rbe_left;
            if (*tmp).tree_entry.rbe_color == 1 as libc::c_int {
                (*tmp).tree_entry.rbe_color = 0 as libc::c_int;
                (*parent).tree_entry.rbe_color = 1 as libc::c_int;
                tmp = (*parent).tree_entry.rbe_left;
                (*parent).tree_entry.rbe_left = (*tmp).tree_entry.rbe_right;
                if !((*parent).tree_entry.rbe_left).is_null() {
                    (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_parent = parent;
                }
                (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_right = parent;
                (*parent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
                tmp = (*parent).tree_entry.rbe_left;
            }
            if (((*tmp).tree_entry.rbe_left).is_null()
                || (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_color == 0 as libc::c_int)
                && (((*tmp).tree_entry.rbe_right).is_null()
                    || (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_color == 0 as libc::c_int)
            {
                (*tmp).tree_entry.rbe_color = 1 as libc::c_int;
                elm = parent;
                parent = (*elm).tree_entry.rbe_parent;
            } else {
                if ((*tmp).tree_entry.rbe_left).is_null()
                    || (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_color == 0 as libc::c_int
                {
                    let mut oright: *mut revoked_key_id = 0 as *mut revoked_key_id;
                    oright = (*tmp).tree_entry.rbe_right;
                    if !oright.is_null() {
                        (*oright).tree_entry.rbe_color = 0 as libc::c_int;
                    }
                    (*tmp).tree_entry.rbe_color = 1 as libc::c_int;
                    oright = (*tmp).tree_entry.rbe_right;
                    (*tmp).tree_entry.rbe_right = (*oright).tree_entry.rbe_left;
                    if !((*tmp).tree_entry.rbe_right).is_null() {
                        (*(*oright).tree_entry.rbe_left).tree_entry.rbe_parent = tmp;
                    }
                    (*oright).tree_entry.rbe_parent = (*tmp).tree_entry.rbe_parent;
                    if !((*oright).tree_entry.rbe_parent).is_null() {
                        if tmp == (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_left {
                            (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_left = oright;
                        } else {
                            (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_right = oright;
                        }
                    } else {
                        (*head).rbh_root = oright;
                    }
                    (*oright).tree_entry.rbe_left = tmp;
                    (*tmp).tree_entry.rbe_parent = oright;
                    !((*oright).tree_entry.rbe_parent).is_null();
                    tmp = (*parent).tree_entry.rbe_left;
                }
                (*tmp).tree_entry.rbe_color = (*parent).tree_entry.rbe_color;
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                if !((*tmp).tree_entry.rbe_left).is_null() {
                    (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_color = 0 as libc::c_int;
                }
                tmp = (*parent).tree_entry.rbe_left;
                (*parent).tree_entry.rbe_left = (*tmp).tree_entry.rbe_right;
                if !((*parent).tree_entry.rbe_left).is_null() {
                    (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_parent = parent;
                }
                (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_right = parent;
                (*parent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
                elm = (*head).rbh_root;
                break;
            }
        }
    }
    if !elm.is_null() {
        (*elm).tree_entry.rbe_color = 0 as libc::c_int;
    }
}
unsafe extern "C" fn revoked_key_id_tree_RB_REMOVE(
    mut head: *mut revoked_key_id_tree,
    mut elm: *mut revoked_key_id,
) -> *mut revoked_key_id {
    let mut current_block: u64;
    let mut child: *mut revoked_key_id = 0 as *mut revoked_key_id;
    let mut parent: *mut revoked_key_id = 0 as *mut revoked_key_id;
    let mut old: *mut revoked_key_id = elm;
    let mut color: libc::c_int = 0;
    if ((*elm).tree_entry.rbe_left).is_null() {
        child = (*elm).tree_entry.rbe_right;
        current_block = 7245201122033322888;
    } else if ((*elm).tree_entry.rbe_right).is_null() {
        child = (*elm).tree_entry.rbe_left;
        current_block = 7245201122033322888;
    } else {
        let mut left: *mut revoked_key_id = 0 as *mut revoked_key_id;
        elm = (*elm).tree_entry.rbe_right;
        loop {
            left = (*elm).tree_entry.rbe_left;
            if left.is_null() {
                break;
            }
            elm = left;
        }
        child = (*elm).tree_entry.rbe_right;
        parent = (*elm).tree_entry.rbe_parent;
        color = (*elm).tree_entry.rbe_color;
        if !child.is_null() {
            (*child).tree_entry.rbe_parent = parent;
        }
        if !parent.is_null() {
            if (*parent).tree_entry.rbe_left == elm {
                (*parent).tree_entry.rbe_left = child;
            } else {
                (*parent).tree_entry.rbe_right = child;
            }
        } else {
            (*head).rbh_root = child;
        }
        if (*elm).tree_entry.rbe_parent == old {
            parent = elm;
        }
        (*elm).tree_entry = (*old).tree_entry;
        if !((*old).tree_entry.rbe_parent).is_null() {
            if (*(*old).tree_entry.rbe_parent).tree_entry.rbe_left == old {
                (*(*old).tree_entry.rbe_parent).tree_entry.rbe_left = elm;
            } else {
                (*(*old).tree_entry.rbe_parent).tree_entry.rbe_right = elm;
            }
        } else {
            (*head).rbh_root = elm;
        }
        (*(*old).tree_entry.rbe_left).tree_entry.rbe_parent = elm;
        if !((*old).tree_entry.rbe_right).is_null() {
            (*(*old).tree_entry.rbe_right).tree_entry.rbe_parent = elm;
        }
        if !parent.is_null() {
            left = parent;
            loop {
                left = (*left).tree_entry.rbe_parent;
                if left.is_null() {
                    break;
                }
            }
        }
        current_block = 6858191600374679769;
    }
    match current_block {
        7245201122033322888 => {
            parent = (*elm).tree_entry.rbe_parent;
            color = (*elm).tree_entry.rbe_color;
            if !child.is_null() {
                (*child).tree_entry.rbe_parent = parent;
            }
            if !parent.is_null() {
                if (*parent).tree_entry.rbe_left == elm {
                    (*parent).tree_entry.rbe_left = child;
                } else {
                    (*parent).tree_entry.rbe_right = child;
                }
            } else {
                (*head).rbh_root = child;
            }
        }
        _ => {}
    }
    if color == 0 as libc::c_int {
        revoked_key_id_tree_RB_REMOVE_COLOR(head, parent, child);
    }
    return old;
}
unsafe extern "C" fn revoked_blob_tree_RB_REMOVE_COLOR(
    mut head: *mut revoked_blob_tree,
    mut parent: *mut revoked_blob,
    mut elm: *mut revoked_blob,
) {
    let mut tmp: *mut revoked_blob = 0 as *mut revoked_blob;
    while (elm.is_null() || (*elm).tree_entry.rbe_color == 0 as libc::c_int)
        && elm != (*head).rbh_root
    {
        if (*parent).tree_entry.rbe_left == elm {
            tmp = (*parent).tree_entry.rbe_right;
            if (*tmp).tree_entry.rbe_color == 1 as libc::c_int {
                (*tmp).tree_entry.rbe_color = 0 as libc::c_int;
                (*parent).tree_entry.rbe_color = 1 as libc::c_int;
                tmp = (*parent).tree_entry.rbe_right;
                (*parent).tree_entry.rbe_right = (*tmp).tree_entry.rbe_left;
                if !((*parent).tree_entry.rbe_right).is_null() {
                    (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_parent = parent;
                }
                (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_left = parent;
                (*parent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
                tmp = (*parent).tree_entry.rbe_right;
            }
            if (((*tmp).tree_entry.rbe_left).is_null()
                || (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_color == 0 as libc::c_int)
                && (((*tmp).tree_entry.rbe_right).is_null()
                    || (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_color == 0 as libc::c_int)
            {
                (*tmp).tree_entry.rbe_color = 1 as libc::c_int;
                elm = parent;
                parent = (*elm).tree_entry.rbe_parent;
            } else {
                if ((*tmp).tree_entry.rbe_right).is_null()
                    || (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_color == 0 as libc::c_int
                {
                    let mut oleft: *mut revoked_blob = 0 as *mut revoked_blob;
                    oleft = (*tmp).tree_entry.rbe_left;
                    if !oleft.is_null() {
                        (*oleft).tree_entry.rbe_color = 0 as libc::c_int;
                    }
                    (*tmp).tree_entry.rbe_color = 1 as libc::c_int;
                    oleft = (*tmp).tree_entry.rbe_left;
                    (*tmp).tree_entry.rbe_left = (*oleft).tree_entry.rbe_right;
                    if !((*tmp).tree_entry.rbe_left).is_null() {
                        (*(*oleft).tree_entry.rbe_right).tree_entry.rbe_parent = tmp;
                    }
                    (*oleft).tree_entry.rbe_parent = (*tmp).tree_entry.rbe_parent;
                    if !((*oleft).tree_entry.rbe_parent).is_null() {
                        if tmp == (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_left {
                            (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_left = oleft;
                        } else {
                            (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_right = oleft;
                        }
                    } else {
                        (*head).rbh_root = oleft;
                    }
                    (*oleft).tree_entry.rbe_right = tmp;
                    (*tmp).tree_entry.rbe_parent = oleft;
                    !((*oleft).tree_entry.rbe_parent).is_null();
                    tmp = (*parent).tree_entry.rbe_right;
                }
                (*tmp).tree_entry.rbe_color = (*parent).tree_entry.rbe_color;
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                if !((*tmp).tree_entry.rbe_right).is_null() {
                    (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_color = 0 as libc::c_int;
                }
                tmp = (*parent).tree_entry.rbe_right;
                (*parent).tree_entry.rbe_right = (*tmp).tree_entry.rbe_left;
                if !((*parent).tree_entry.rbe_right).is_null() {
                    (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_parent = parent;
                }
                (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_left = parent;
                (*parent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
                elm = (*head).rbh_root;
                break;
            }
        } else {
            tmp = (*parent).tree_entry.rbe_left;
            if (*tmp).tree_entry.rbe_color == 1 as libc::c_int {
                (*tmp).tree_entry.rbe_color = 0 as libc::c_int;
                (*parent).tree_entry.rbe_color = 1 as libc::c_int;
                tmp = (*parent).tree_entry.rbe_left;
                (*parent).tree_entry.rbe_left = (*tmp).tree_entry.rbe_right;
                if !((*parent).tree_entry.rbe_left).is_null() {
                    (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_parent = parent;
                }
                (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_right = parent;
                (*parent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
                tmp = (*parent).tree_entry.rbe_left;
            }
            if (((*tmp).tree_entry.rbe_left).is_null()
                || (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_color == 0 as libc::c_int)
                && (((*tmp).tree_entry.rbe_right).is_null()
                    || (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_color == 0 as libc::c_int)
            {
                (*tmp).tree_entry.rbe_color = 1 as libc::c_int;
                elm = parent;
                parent = (*elm).tree_entry.rbe_parent;
            } else {
                if ((*tmp).tree_entry.rbe_left).is_null()
                    || (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_color == 0 as libc::c_int
                {
                    let mut oright: *mut revoked_blob = 0 as *mut revoked_blob;
                    oright = (*tmp).tree_entry.rbe_right;
                    if !oright.is_null() {
                        (*oright).tree_entry.rbe_color = 0 as libc::c_int;
                    }
                    (*tmp).tree_entry.rbe_color = 1 as libc::c_int;
                    oright = (*tmp).tree_entry.rbe_right;
                    (*tmp).tree_entry.rbe_right = (*oright).tree_entry.rbe_left;
                    if !((*tmp).tree_entry.rbe_right).is_null() {
                        (*(*oright).tree_entry.rbe_left).tree_entry.rbe_parent = tmp;
                    }
                    (*oright).tree_entry.rbe_parent = (*tmp).tree_entry.rbe_parent;
                    if !((*oright).tree_entry.rbe_parent).is_null() {
                        if tmp == (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_left {
                            (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_left = oright;
                        } else {
                            (*(*tmp).tree_entry.rbe_parent).tree_entry.rbe_right = oright;
                        }
                    } else {
                        (*head).rbh_root = oright;
                    }
                    (*oright).tree_entry.rbe_left = tmp;
                    (*tmp).tree_entry.rbe_parent = oright;
                    !((*oright).tree_entry.rbe_parent).is_null();
                    tmp = (*parent).tree_entry.rbe_left;
                }
                (*tmp).tree_entry.rbe_color = (*parent).tree_entry.rbe_color;
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                if !((*tmp).tree_entry.rbe_left).is_null() {
                    (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_color = 0 as libc::c_int;
                }
                tmp = (*parent).tree_entry.rbe_left;
                (*parent).tree_entry.rbe_left = (*tmp).tree_entry.rbe_right;
                if !((*parent).tree_entry.rbe_left).is_null() {
                    (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_parent = parent;
                }
                (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_right = parent;
                (*parent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
                elm = (*head).rbh_root;
                break;
            }
        }
    }
    if !elm.is_null() {
        (*elm).tree_entry.rbe_color = 0 as libc::c_int;
    }
}
unsafe extern "C" fn revoked_blob_tree_RB_INSERT_COLOR(
    mut head: *mut revoked_blob_tree,
    mut elm: *mut revoked_blob,
) {
    let mut parent: *mut revoked_blob = 0 as *mut revoked_blob;
    let mut gparent: *mut revoked_blob = 0 as *mut revoked_blob;
    let mut tmp: *mut revoked_blob = 0 as *mut revoked_blob;
    loop {
        parent = (*elm).tree_entry.rbe_parent;
        if !(!parent.is_null() && (*parent).tree_entry.rbe_color == 1 as libc::c_int) {
            break;
        }
        gparent = (*parent).tree_entry.rbe_parent;
        if parent == (*gparent).tree_entry.rbe_left {
            tmp = (*gparent).tree_entry.rbe_right;
            if !tmp.is_null() && (*tmp).tree_entry.rbe_color == 1 as libc::c_int {
                (*tmp).tree_entry.rbe_color = 0 as libc::c_int;
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                (*gparent).tree_entry.rbe_color = 1 as libc::c_int;
                elm = gparent;
            } else {
                if (*parent).tree_entry.rbe_right == elm {
                    tmp = (*parent).tree_entry.rbe_right;
                    (*parent).tree_entry.rbe_right = (*tmp).tree_entry.rbe_left;
                    if !((*parent).tree_entry.rbe_right).is_null() {
                        (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_parent = parent;
                    }
                    (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                    if !((*tmp).tree_entry.rbe_parent).is_null() {
                        if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                            (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                        } else {
                            (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                        }
                    } else {
                        (*head).rbh_root = tmp;
                    }
                    (*tmp).tree_entry.rbe_left = parent;
                    (*parent).tree_entry.rbe_parent = tmp;
                    !((*tmp).tree_entry.rbe_parent).is_null();
                    tmp = parent;
                    parent = elm;
                    elm = tmp;
                }
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                (*gparent).tree_entry.rbe_color = 1 as libc::c_int;
                tmp = (*gparent).tree_entry.rbe_left;
                (*gparent).tree_entry.rbe_left = (*tmp).tree_entry.rbe_right;
                if !((*gparent).tree_entry.rbe_left).is_null() {
                    (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_parent = gparent;
                }
                (*tmp).tree_entry.rbe_parent = (*gparent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if gparent == (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_right = gparent;
                (*gparent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
            }
        } else {
            tmp = (*gparent).tree_entry.rbe_left;
            if !tmp.is_null() && (*tmp).tree_entry.rbe_color == 1 as libc::c_int {
                (*tmp).tree_entry.rbe_color = 0 as libc::c_int;
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                (*gparent).tree_entry.rbe_color = 1 as libc::c_int;
                elm = gparent;
            } else {
                if (*parent).tree_entry.rbe_left == elm {
                    tmp = (*parent).tree_entry.rbe_left;
                    (*parent).tree_entry.rbe_left = (*tmp).tree_entry.rbe_right;
                    if !((*parent).tree_entry.rbe_left).is_null() {
                        (*(*tmp).tree_entry.rbe_right).tree_entry.rbe_parent = parent;
                    }
                    (*tmp).tree_entry.rbe_parent = (*parent).tree_entry.rbe_parent;
                    if !((*tmp).tree_entry.rbe_parent).is_null() {
                        if parent == (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left {
                            (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                        } else {
                            (*(*parent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                        }
                    } else {
                        (*head).rbh_root = tmp;
                    }
                    (*tmp).tree_entry.rbe_right = parent;
                    (*parent).tree_entry.rbe_parent = tmp;
                    !((*tmp).tree_entry.rbe_parent).is_null();
                    tmp = parent;
                    parent = elm;
                    elm = tmp;
                }
                (*parent).tree_entry.rbe_color = 0 as libc::c_int;
                (*gparent).tree_entry.rbe_color = 1 as libc::c_int;
                tmp = (*gparent).tree_entry.rbe_right;
                (*gparent).tree_entry.rbe_right = (*tmp).tree_entry.rbe_left;
                if !((*gparent).tree_entry.rbe_right).is_null() {
                    (*(*tmp).tree_entry.rbe_left).tree_entry.rbe_parent = gparent;
                }
                (*tmp).tree_entry.rbe_parent = (*gparent).tree_entry.rbe_parent;
                if !((*tmp).tree_entry.rbe_parent).is_null() {
                    if gparent == (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_left {
                        (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_left = tmp;
                    } else {
                        (*(*gparent).tree_entry.rbe_parent).tree_entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).tree_entry.rbe_left = gparent;
                (*gparent).tree_entry.rbe_parent = tmp;
                !((*tmp).tree_entry.rbe_parent).is_null();
            }
        }
    }
    (*(*head).rbh_root).tree_entry.rbe_color = 0 as libc::c_int;
}
unsafe extern "C" fn revoked_blob_tree_RB_INSERT(
    mut head: *mut revoked_blob_tree,
    mut elm: *mut revoked_blob,
) -> *mut revoked_blob {
    let mut tmp: *mut revoked_blob = 0 as *mut revoked_blob;
    let mut parent: *mut revoked_blob = 0 as *mut revoked_blob;
    let mut comp: libc::c_int = 0 as libc::c_int;
    tmp = (*head).rbh_root;
    while !tmp.is_null() {
        parent = tmp;
        comp = blob_cmp(elm, parent);
        if comp < 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_left;
        } else if comp > 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_right;
        } else {
            return tmp;
        }
    }
    (*elm).tree_entry.rbe_parent = parent;
    (*elm).tree_entry.rbe_right = 0 as *mut revoked_blob;
    (*elm).tree_entry.rbe_left = (*elm).tree_entry.rbe_right;
    (*elm).tree_entry.rbe_color = 1 as libc::c_int;
    if !parent.is_null() {
        if comp < 0 as libc::c_int {
            (*parent).tree_entry.rbe_left = elm;
        } else {
            (*parent).tree_entry.rbe_right = elm;
        }
    } else {
        (*head).rbh_root = elm;
    }
    revoked_blob_tree_RB_INSERT_COLOR(head, elm);
    return 0 as *mut revoked_blob;
}
unsafe extern "C" fn revoked_blob_tree_RB_REMOVE(
    mut head: *mut revoked_blob_tree,
    mut elm: *mut revoked_blob,
) -> *mut revoked_blob {
    let mut current_block: u64;
    let mut child: *mut revoked_blob = 0 as *mut revoked_blob;
    let mut parent: *mut revoked_blob = 0 as *mut revoked_blob;
    let mut old: *mut revoked_blob = elm;
    let mut color: libc::c_int = 0;
    if ((*elm).tree_entry.rbe_left).is_null() {
        child = (*elm).tree_entry.rbe_right;
        current_block = 7245201122033322888;
    } else if ((*elm).tree_entry.rbe_right).is_null() {
        child = (*elm).tree_entry.rbe_left;
        current_block = 7245201122033322888;
    } else {
        let mut left: *mut revoked_blob = 0 as *mut revoked_blob;
        elm = (*elm).tree_entry.rbe_right;
        loop {
            left = (*elm).tree_entry.rbe_left;
            if left.is_null() {
                break;
            }
            elm = left;
        }
        child = (*elm).tree_entry.rbe_right;
        parent = (*elm).tree_entry.rbe_parent;
        color = (*elm).tree_entry.rbe_color;
        if !child.is_null() {
            (*child).tree_entry.rbe_parent = parent;
        }
        if !parent.is_null() {
            if (*parent).tree_entry.rbe_left == elm {
                (*parent).tree_entry.rbe_left = child;
            } else {
                (*parent).tree_entry.rbe_right = child;
            }
        } else {
            (*head).rbh_root = child;
        }
        if (*elm).tree_entry.rbe_parent == old {
            parent = elm;
        }
        (*elm).tree_entry = (*old).tree_entry;
        if !((*old).tree_entry.rbe_parent).is_null() {
            if (*(*old).tree_entry.rbe_parent).tree_entry.rbe_left == old {
                (*(*old).tree_entry.rbe_parent).tree_entry.rbe_left = elm;
            } else {
                (*(*old).tree_entry.rbe_parent).tree_entry.rbe_right = elm;
            }
        } else {
            (*head).rbh_root = elm;
        }
        (*(*old).tree_entry.rbe_left).tree_entry.rbe_parent = elm;
        if !((*old).tree_entry.rbe_right).is_null() {
            (*(*old).tree_entry.rbe_right).tree_entry.rbe_parent = elm;
        }
        if !parent.is_null() {
            left = parent;
            loop {
                left = (*left).tree_entry.rbe_parent;
                if left.is_null() {
                    break;
                }
            }
        }
        current_block = 11314247314407801245;
    }
    match current_block {
        7245201122033322888 => {
            parent = (*elm).tree_entry.rbe_parent;
            color = (*elm).tree_entry.rbe_color;
            if !child.is_null() {
                (*child).tree_entry.rbe_parent = parent;
            }
            if !parent.is_null() {
                if (*parent).tree_entry.rbe_left == elm {
                    (*parent).tree_entry.rbe_left = child;
                } else {
                    (*parent).tree_entry.rbe_right = child;
                }
            } else {
                (*head).rbh_root = child;
            }
        }
        _ => {}
    }
    if color == 0 as libc::c_int {
        revoked_blob_tree_RB_REMOVE_COLOR(head, parent, child);
    }
    return old;
}
unsafe extern "C" fn revoked_blob_tree_RB_FIND(
    mut head: *mut revoked_blob_tree,
    mut elm: *mut revoked_blob,
) -> *mut revoked_blob {
    let mut tmp: *mut revoked_blob = (*head).rbh_root;
    let mut comp: libc::c_int = 0;
    while !tmp.is_null() {
        comp = blob_cmp(elm, tmp);
        if comp < 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_left;
        } else if comp > 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_right;
        } else {
            return tmp;
        }
    }
    return 0 as *mut revoked_blob;
}
unsafe extern "C" fn revoked_blob_tree_RB_NEXT(mut elm: *mut revoked_blob) -> *mut revoked_blob {
    if !((*elm).tree_entry.rbe_right).is_null() {
        elm = (*elm).tree_entry.rbe_right;
        while !((*elm).tree_entry.rbe_left).is_null() {
            elm = (*elm).tree_entry.rbe_left;
        }
    } else if !((*elm).tree_entry.rbe_parent).is_null()
        && elm == (*(*elm).tree_entry.rbe_parent).tree_entry.rbe_left
    {
        elm = (*elm).tree_entry.rbe_parent;
    } else {
        while !((*elm).tree_entry.rbe_parent).is_null()
            && elm == (*(*elm).tree_entry.rbe_parent).tree_entry.rbe_right
        {
            elm = (*elm).tree_entry.rbe_parent;
        }
        elm = (*elm).tree_entry.rbe_parent;
    }
    return elm;
}
unsafe extern "C" fn revoked_blob_tree_RB_MINMAX(
    mut head: *mut revoked_blob_tree,
    mut val: libc::c_int,
) -> *mut revoked_blob {
    let mut tmp: *mut revoked_blob = (*head).rbh_root;
    let mut parent: *mut revoked_blob = 0 as *mut revoked_blob;
    while !tmp.is_null() {
        parent = tmp;
        if val < 0 as libc::c_int {
            tmp = (*tmp).tree_entry.rbe_left;
        } else {
            tmp = (*tmp).tree_entry.rbe_right;
        }
    }
    return parent;
}
unsafe extern "C" fn serial_cmp(
    mut a: *mut revoked_serial,
    mut b: *mut revoked_serial,
) -> libc::c_int {
    if (*a).hi >= (*b).lo && (*a).lo <= (*b).hi {
        return 0 as libc::c_int;
    }
    return if (*a).lo < (*b).lo {
        -(1 as libc::c_int)
    } else {
        1 as libc::c_int
    };
}
unsafe extern "C" fn key_id_cmp(
    mut a: *mut revoked_key_id,
    mut b: *mut revoked_key_id,
) -> libc::c_int {
    return strcmp((*a).key_id, (*b).key_id);
}
unsafe extern "C" fn blob_cmp(mut a: *mut revoked_blob, mut b: *mut revoked_blob) -> libc::c_int {
    let mut r: libc::c_int = 0;
    if (*a).len != (*b).len {
        r = memcmp(
            (*a).blob as *const libc::c_void,
            (*b).blob as *const libc::c_void,
            if (*a).len < (*b).len {
                (*a).len
            } else {
                (*b).len
            },
        );
        if r != 0 as libc::c_int {
            return r;
        }
        return if (*a).len > (*b).len {
            1 as libc::c_int
        } else {
            -(1 as libc::c_int)
        };
    } else {
        return memcmp(
            (*a).blob as *const libc::c_void,
            (*b).blob as *const libc::c_void,
            (*a).len,
        );
    };
}
pub unsafe extern "C" fn ssh_krl_init() -> *mut ssh_krl {
    let mut krl: *mut ssh_krl = 0 as *mut ssh_krl;
    krl = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<ssh_krl>() as libc::c_ulong,
    ) as *mut ssh_krl;
    if krl.is_null() {
        return 0 as *mut ssh_krl;
    }
    (*krl).revoked_keys.rbh_root = 0 as *mut revoked_blob;
    (*krl).revoked_sha1s.rbh_root = 0 as *mut revoked_blob;
    (*krl).revoked_sha256s.rbh_root = 0 as *mut revoked_blob;
    (*krl).revoked_certs.tqh_first = 0 as *mut revoked_certs;
    (*krl).revoked_certs.tqh_last = &mut (*krl).revoked_certs.tqh_first;
    return krl;
}
unsafe extern "C" fn revoked_certs_free(mut rc: *mut revoked_certs) {
    let mut rs: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut trs: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut rki: *mut revoked_key_id = 0 as *mut revoked_key_id;
    let mut trki: *mut revoked_key_id = 0 as *mut revoked_key_id;
    rs = revoked_serial_tree_RB_MINMAX(&mut (*rc).revoked_serials, -(1 as libc::c_int));
    while !rs.is_null() && {
        trs = revoked_serial_tree_RB_NEXT(rs);
        1 as libc::c_int != 0
    } {
        revoked_serial_tree_RB_REMOVE(&mut (*rc).revoked_serials, rs);
        free(rs as *mut libc::c_void);
        rs = trs;
    }
    rki = revoked_key_id_tree_RB_MINMAX(&mut (*rc).revoked_key_ids, -(1 as libc::c_int));
    while !rki.is_null() && {
        trki = revoked_key_id_tree_RB_NEXT(rki);
        1 as libc::c_int != 0
    } {
        revoked_key_id_tree_RB_REMOVE(&mut (*rc).revoked_key_ids, rki);
        free((*rki).key_id as *mut libc::c_void);
        free(rki as *mut libc::c_void);
        rki = trki;
    }
    sshkey_free((*rc).ca_key);
}
pub unsafe extern "C" fn ssh_krl_free(mut krl: *mut ssh_krl) {
    let mut rb: *mut revoked_blob = 0 as *mut revoked_blob;
    let mut trb: *mut revoked_blob = 0 as *mut revoked_blob;
    let mut rc: *mut revoked_certs = 0 as *mut revoked_certs;
    let mut trc: *mut revoked_certs = 0 as *mut revoked_certs;
    if krl.is_null() {
        return;
    }
    free((*krl).comment as *mut libc::c_void);
    rb = revoked_blob_tree_RB_MINMAX(&mut (*krl).revoked_keys, -(1 as libc::c_int));
    while !rb.is_null() && {
        trb = revoked_blob_tree_RB_NEXT(rb);
        1 as libc::c_int != 0
    } {
        revoked_blob_tree_RB_REMOVE(&mut (*krl).revoked_keys, rb);
        free((*rb).blob as *mut libc::c_void);
        free(rb as *mut libc::c_void);
        rb = trb;
    }
    rb = revoked_blob_tree_RB_MINMAX(&mut (*krl).revoked_sha1s, -(1 as libc::c_int));
    while !rb.is_null() && {
        trb = revoked_blob_tree_RB_NEXT(rb);
        1 as libc::c_int != 0
    } {
        revoked_blob_tree_RB_REMOVE(&mut (*krl).revoked_sha1s, rb);
        free((*rb).blob as *mut libc::c_void);
        free(rb as *mut libc::c_void);
        rb = trb;
    }
    rb = revoked_blob_tree_RB_MINMAX(&mut (*krl).revoked_sha256s, -(1 as libc::c_int));
    while !rb.is_null() && {
        trb = revoked_blob_tree_RB_NEXT(rb);
        1 as libc::c_int != 0
    } {
        revoked_blob_tree_RB_REMOVE(&mut (*krl).revoked_sha256s, rb);
        free((*rb).blob as *mut libc::c_void);
        free(rb as *mut libc::c_void);
        rb = trb;
    }
    rc = (*krl).revoked_certs.tqh_first;
    while !rc.is_null() && {
        trc = (*rc).entry.tqe_next;
        1 as libc::c_int != 0
    } {
        if !((*rc).entry.tqe_next).is_null() {
            (*(*rc).entry.tqe_next).entry.tqe_prev = (*rc).entry.tqe_prev;
        } else {
            (*krl).revoked_certs.tqh_last = (*rc).entry.tqe_prev;
        }
        *(*rc).entry.tqe_prev = (*rc).entry.tqe_next;
        revoked_certs_free(rc);
        rc = trc;
    }
    free(krl as *mut libc::c_void);
}
pub unsafe extern "C" fn ssh_krl_set_version(mut krl: *mut ssh_krl, mut version: u_int64_t) {
    (*krl).krl_version = version;
}
pub unsafe extern "C" fn ssh_krl_set_comment(
    mut krl: *mut ssh_krl,
    mut comment: *const libc::c_char,
) -> libc::c_int {
    free((*krl).comment as *mut libc::c_void);
    (*krl).comment = strdup(comment);
    if ((*krl).comment).is_null() {
        return -(2 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn revoked_certs_for_ca_key(
    mut krl: *mut ssh_krl,
    mut ca_key: *const sshkey,
    mut rcp: *mut *mut revoked_certs,
    mut allow_create: libc::c_int,
) -> libc::c_int {
    let mut rc: *mut revoked_certs = 0 as *mut revoked_certs;
    let mut r: libc::c_int = 0;
    *rcp = 0 as *mut revoked_certs;
    rc = (*krl).revoked_certs.tqh_first;
    while !rc.is_null() {
        if ca_key.is_null() && ((*rc).ca_key).is_null() || sshkey_equal((*rc).ca_key, ca_key) != 0 {
            *rcp = rc;
            return 0 as libc::c_int;
        }
        rc = (*rc).entry.tqe_next;
    }
    if allow_create == 0 {
        return 0 as libc::c_int;
    }
    rc = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<revoked_certs>() as libc::c_ulong,
    ) as *mut revoked_certs;
    if rc.is_null() {
        return -(2 as libc::c_int);
    }
    if ca_key.is_null() {
        (*rc).ca_key = 0 as *mut sshkey;
    } else {
        r = sshkey_from_private(ca_key, &mut (*rc).ca_key);
        if r != 0 as libc::c_int {
            free(rc as *mut libc::c_void);
            return r;
        }
    }
    (*rc).revoked_serials.rbh_root = 0 as *mut revoked_serial;
    (*rc).revoked_key_ids.rbh_root = 0 as *mut revoked_key_id;
    (*rc).entry.tqe_next = 0 as *mut revoked_certs;
    (*rc).entry.tqe_prev = (*krl).revoked_certs.tqh_last;
    *(*krl).revoked_certs.tqh_last = rc;
    (*krl).revoked_certs.tqh_last = &mut (*rc).entry.tqe_next;
    *rcp = rc;
    return 0 as libc::c_int;
}
unsafe extern "C" fn insert_serial_range(
    mut rt: *mut revoked_serial_tree,
    mut lo: u_int64_t,
    mut hi: u_int64_t,
) -> libc::c_int {
    let mut rs: revoked_serial = revoked_serial {
        lo: 0,
        hi: 0,
        tree_entry: C2RustUnnamed_1 {
            rbe_left: 0 as *mut revoked_serial,
            rbe_right: 0 as *mut revoked_serial,
            rbe_parent: 0 as *mut revoked_serial,
            rbe_color: 0,
        },
    };
    let mut ers: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut crs: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut irs: *mut revoked_serial = 0 as *mut revoked_serial;
    memset(
        &mut rs as *mut revoked_serial as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<revoked_serial>() as libc::c_ulong,
    );
    rs.lo = lo;
    rs.hi = hi;
    ers = revoked_serial_tree_RB_NFIND(rt, &mut rs);
    if ers.is_null() || serial_cmp(ers, &mut rs) != 0 as libc::c_int {
        irs = malloc(::core::mem::size_of::<revoked_serial>() as libc::c_ulong)
            as *mut revoked_serial;
        if irs.is_null() {
            return -(2 as libc::c_int);
        }
        memcpy(
            irs as *mut libc::c_void,
            &mut rs as *mut revoked_serial as *const libc::c_void,
            ::core::mem::size_of::<revoked_serial>() as libc::c_ulong,
        );
        ers = revoked_serial_tree_RB_INSERT(rt, irs);
        if !ers.is_null() {
            free(irs as *mut libc::c_void);
            return -(1 as libc::c_int);
        }
        ers = irs;
    } else {
        if (*ers).lo > lo {
            (*ers).lo = lo;
        }
        if (*ers).hi < hi {
            (*ers).hi = hi;
        }
    }
    loop {
        crs = revoked_serial_tree_RB_PREV(ers);
        if crs.is_null() {
            break;
        }
        if (*ers).lo != 0 as libc::c_int as libc::c_ulong
            && (*crs).hi < ((*ers).lo).wrapping_sub(1 as libc::c_int as libc::c_ulong)
        {
            break;
        }
        if (*crs).lo < (*ers).lo {
            (*ers).lo = (*crs).lo;
        }
        revoked_serial_tree_RB_REMOVE(rt, crs);
        free(crs as *mut libc::c_void);
    }
    loop {
        crs = revoked_serial_tree_RB_NEXT(ers);
        if crs.is_null() {
            break;
        }
        if (*ers).hi != -(1 as libc::c_int) as u_int64_t
            && (*crs).lo > ((*ers).hi).wrapping_add(1 as libc::c_int as libc::c_ulong)
        {
            break;
        }
        if (*crs).hi > (*ers).hi {
            (*ers).hi = (*crs).hi;
        }
        revoked_serial_tree_RB_REMOVE(rt, crs);
        free(crs as *mut libc::c_void);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_krl_revoke_cert_by_serial(
    mut krl: *mut ssh_krl,
    mut ca_key: *const sshkey,
    mut serial: u_int64_t,
) -> libc::c_int {
    return ssh_krl_revoke_cert_by_serial_range(krl, ca_key, serial, serial);
}
pub unsafe extern "C" fn ssh_krl_revoke_cert_by_serial_range(
    mut krl: *mut ssh_krl,
    mut ca_key: *const sshkey,
    mut lo: u_int64_t,
    mut hi: u_int64_t,
) -> libc::c_int {
    let mut rc: *mut revoked_certs = 0 as *mut revoked_certs;
    let mut r: libc::c_int = 0;
    if lo > hi || lo == 0 as libc::c_int as libc::c_ulong {
        return -(10 as libc::c_int);
    }
    r = revoked_certs_for_ca_key(krl, ca_key, &mut rc, 1 as libc::c_int);
    if r != 0 as libc::c_int {
        return r;
    }
    return insert_serial_range(&mut (*rc).revoked_serials, lo, hi);
}
pub unsafe extern "C" fn ssh_krl_revoke_cert_by_key_id(
    mut krl: *mut ssh_krl,
    mut ca_key: *const sshkey,
    mut key_id: *const libc::c_char,
) -> libc::c_int {
    let mut rki: *mut revoked_key_id = 0 as *mut revoked_key_id;
    let mut erki: *mut revoked_key_id = 0 as *mut revoked_key_id;
    let mut rc: *mut revoked_certs = 0 as *mut revoked_certs;
    let mut r: libc::c_int = 0;
    r = revoked_certs_for_ca_key(krl, ca_key, &mut rc, 1 as libc::c_int);
    if r != 0 as libc::c_int {
        return r;
    }
    rki = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<revoked_key_id>() as libc::c_ulong,
    ) as *mut revoked_key_id;
    if rki.is_null() || {
        (*rki).key_id = strdup(key_id);
        ((*rki).key_id).is_null()
    } {
        free(rki as *mut libc::c_void);
        return -(2 as libc::c_int);
    }
    erki = revoked_key_id_tree_RB_INSERT(&mut (*rc).revoked_key_ids, rki);
    if !erki.is_null() {
        free((*rki).key_id as *mut libc::c_void);
        free(rki as *mut libc::c_void);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn plain_key_blob(
    mut key: *const sshkey,
    mut blob: *mut *mut u_char,
    mut blen: *mut size_t,
) -> libc::c_int {
    let mut kcopy: *mut sshkey = 0 as *mut sshkey;
    let mut r: libc::c_int = 0;
    r = sshkey_from_private(key, &mut kcopy);
    if r != 0 as libc::c_int {
        return r;
    }
    if sshkey_is_cert(kcopy) != 0 {
        r = sshkey_drop_cert(kcopy);
        if r != 0 as libc::c_int {
            sshkey_free(kcopy);
            return r;
        }
    }
    r = sshkey_to_blob(kcopy, blob, blen);
    sshkey_free(kcopy);
    return r;
}
unsafe extern "C" fn revoke_blob(
    mut rbt: *mut revoked_blob_tree,
    mut blob: *mut u_char,
    mut len: size_t,
) -> libc::c_int {
    let mut rb: *mut revoked_blob = 0 as *mut revoked_blob;
    let mut erb: *mut revoked_blob = 0 as *mut revoked_blob;
    rb = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<revoked_blob>() as libc::c_ulong,
    ) as *mut revoked_blob;
    if rb.is_null() {
        return -(2 as libc::c_int);
    }
    (*rb).blob = blob;
    (*rb).len = len;
    erb = revoked_blob_tree_RB_INSERT(rbt, rb);
    if !erb.is_null() {
        free((*rb).blob as *mut libc::c_void);
        free(rb as *mut libc::c_void);
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_krl_revoke_key_explicit(
    mut krl: *mut ssh_krl,
    mut key: *const sshkey,
) -> libc::c_int {
    let mut blob: *mut u_char = 0 as *mut u_char;
    let mut len: size_t = 0;
    let mut r: libc::c_int = 0;
    crate::log::sshlog(
        b"krl.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 28], &[libc::c_char; 28]>(
            b"ssh_krl_revoke_key_explicit\0",
        ))
        .as_ptr(),
        411 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"revoke type %s\0" as *const u8 as *const libc::c_char,
        sshkey_type(key),
    );
    r = plain_key_blob(key, &mut blob, &mut len);
    if r != 0 as libc::c_int {
        return r;
    }
    return revoke_blob(&mut (*krl).revoked_keys, blob, len);
}
unsafe extern "C" fn revoke_by_hash(
    mut target: *mut revoked_blob_tree,
    mut p: *const u_char,
    mut len: size_t,
) -> libc::c_int {
    let mut blob: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    blob = malloc(len) as *mut u_char;
    if blob.is_null() {
        return -(24 as libc::c_int);
    }
    memcpy(blob as *mut libc::c_void, p as *const libc::c_void, len);
    r = revoke_blob(target, blob, len);
    if r != 0 as libc::c_int {
        free(blob as *mut libc::c_void);
        return r;
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_krl_revoke_key_sha1(
    mut krl: *mut ssh_krl,
    mut p: *const u_char,
    mut len: size_t,
) -> libc::c_int {
    crate::log::sshlog(
        b"krl.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(b"ssh_krl_revoke_key_sha1\0"))
            .as_ptr(),
        437 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"revoke by sha1\0" as *const u8 as *const libc::c_char,
    );
    if len != 20 as libc::c_int as libc::c_ulong {
        return -(4 as libc::c_int);
    }
    return revoke_by_hash(&mut (*krl).revoked_sha1s, p, len);
}
pub unsafe extern "C" fn ssh_krl_revoke_key_sha256(
    mut krl: *mut ssh_krl,
    mut p: *const u_char,
    mut len: size_t,
) -> libc::c_int {
    crate::log::sshlog(
        b"krl.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(b"ssh_krl_revoke_key_sha256\0"))
            .as_ptr(),
        446 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG3,
        0 as *const libc::c_char,
        b"revoke by sha256\0" as *const u8 as *const libc::c_char,
    );
    if len != 32 as libc::c_int as libc::c_ulong {
        return -(4 as libc::c_int);
    }
    return revoke_by_hash(&mut (*krl).revoked_sha256s, p, len);
}
pub unsafe extern "C" fn ssh_krl_revoke_key(
    mut krl: *mut ssh_krl,
    mut key: *const sshkey,
) -> libc::c_int {
    if sshkey_is_cert(key) == 0 {
        return ssh_krl_revoke_key_explicit(krl, key);
    }
    if (*(*key).cert).serial == 0 as libc::c_int as libc::c_ulong {
        return ssh_krl_revoke_cert_by_key_id(
            krl,
            (*(*key).cert).signature_key,
            (*(*key).cert).key_id,
        );
    } else {
        return ssh_krl_revoke_cert_by_serial(
            krl,
            (*(*key).cert).signature_key,
            (*(*key).cert).serial,
        );
    };
}
unsafe extern "C" fn choose_next_state(
    mut current_state: libc::c_int,
    mut contig: u_int64_t,
    mut final_0: libc::c_int,
    mut last_gap: u_int64_t,
    mut next_gap: u_int64_t,
    mut force_new_section: *mut libc::c_int,
) -> libc::c_int {
    let mut new_state: libc::c_int = 0;
    let mut cost: u_int64_t = 0;
    let mut cost_list: u_int64_t = 0;
    let mut cost_range: u_int64_t = 0;
    let mut cost_bitmap: u_int64_t = 0;
    let mut cost_bitmap_restart: u_int64_t = 0;
    contig = (if (contig as libc::c_ulonglong) < (1 as libc::c_ulonglong) << 31 as libc::c_int {
        contig as libc::c_ulonglong
    } else {
        (1 as libc::c_ulonglong) << 31 as libc::c_int
    }) as u_int64_t;
    last_gap = (if (last_gap as libc::c_ulonglong) < (1 as libc::c_ulonglong) << 31 as libc::c_int {
        last_gap as libc::c_ulonglong
    } else {
        (1 as libc::c_ulonglong) << 31 as libc::c_int
    }) as u_int64_t;
    next_gap = (if (next_gap as libc::c_ulonglong) < (1 as libc::c_ulonglong) << 31 as libc::c_int {
        next_gap as libc::c_ulonglong
    } else {
        (1 as libc::c_ulonglong) << 31 as libc::c_int
    }) as u_int64_t;
    cost_bitmap_restart = 0 as libc::c_int as u_int64_t;
    cost_bitmap = cost_bitmap_restart;
    cost_list = cost_bitmap;
    cost_range = 8 as libc::c_int as u_int64_t;
    match current_state {
        32 => {
            cost_bitmap = (8 as libc::c_int + 64 as libc::c_int) as u_int64_t;
            cost_bitmap_restart = cost_bitmap;
        }
        34 => {
            cost_list = 8 as libc::c_int as u_int64_t;
            cost_bitmap_restart = (8 as libc::c_int + 64 as libc::c_int) as u_int64_t;
        }
        33 | 0 => {
            cost_bitmap = (8 as libc::c_int + 64 as libc::c_int) as u_int64_t;
            cost_bitmap_restart = cost_bitmap;
            cost_list = 8 as libc::c_int as u_int64_t;
        }
        _ => {}
    }
    cost_list = (cost_list as libc::c_ulong).wrapping_add(
        (64 as libc::c_int as libc::c_ulong)
            .wrapping_mul(contig)
            .wrapping_add(
                (if final_0 != 0 {
                    0 as libc::c_int
                } else {
                    8 as libc::c_int + 64 as libc::c_int
                }) as libc::c_ulong,
            ),
    ) as u_int64_t as u_int64_t;
    cost_range = (cost_range as libc::c_ulong).wrapping_add(
        (2 as libc::c_int * 64 as libc::c_int
            + (if final_0 != 0 {
                0 as libc::c_int
            } else {
                8 as libc::c_int + 64 as libc::c_int
            })) as libc::c_ulong,
    ) as u_int64_t as u_int64_t;
    cost_bitmap = (cost_bitmap as libc::c_ulong).wrapping_add(
        last_gap.wrapping_add(contig).wrapping_add(if final_0 != 0 {
            0 as libc::c_int as libc::c_ulong
        } else {
            if next_gap < (8 as libc::c_int + 64 as libc::c_int) as libc::c_ulong {
                next_gap
            } else {
                (8 as libc::c_int + 64 as libc::c_int) as libc::c_ulong
            }
        }),
    ) as u_int64_t as u_int64_t;
    cost_bitmap_restart =
        (cost_bitmap_restart as libc::c_ulong).wrapping_add(contig.wrapping_add(if final_0 != 0 {
            0 as libc::c_int as libc::c_ulong
        } else {
            if next_gap < (8 as libc::c_int + 64 as libc::c_int) as libc::c_ulong {
                next_gap
            } else {
                (8 as libc::c_int + 64 as libc::c_int) as libc::c_ulong
            }
        })) as u_int64_t as u_int64_t;
    cost_list = cost_list
        .wrapping_add(7 as libc::c_int as libc::c_ulong)
        .wrapping_div(8 as libc::c_int as libc::c_ulong);
    cost_bitmap = cost_bitmap
        .wrapping_add(7 as libc::c_int as libc::c_ulong)
        .wrapping_div(8 as libc::c_int as libc::c_ulong);
    cost_bitmap_restart = cost_bitmap_restart
        .wrapping_add(7 as libc::c_int as libc::c_ulong)
        .wrapping_div(8 as libc::c_int as libc::c_ulong);
    cost_range = cost_range
        .wrapping_add(7 as libc::c_int as libc::c_ulong)
        .wrapping_div(8 as libc::c_int as libc::c_ulong);
    *force_new_section = 0 as libc::c_int;
    new_state = 0x22 as libc::c_int;
    cost = cost_bitmap;
    if cost_range < cost {
        new_state = 0x21 as libc::c_int;
        cost = cost_range;
    }
    if cost_list < cost {
        new_state = 0x20 as libc::c_int;
        cost = cost_list;
    }
    if cost_bitmap_restart < cost {
        new_state = 0x22 as libc::c_int;
        *force_new_section = 1 as libc::c_int;
        cost = cost_bitmap_restart;
    }
    return new_state;
}
unsafe extern "C" fn put_bitmap(mut buf: *mut sshbuf, mut bitmap: *mut bitmap) -> libc::c_int {
    let mut len: size_t = 0;
    let mut blob: *mut u_char = 0 as *mut u_char;
    let mut r: libc::c_int = 0;
    len = bitmap_nbytes(bitmap);
    blob = malloc(len) as *mut u_char;
    if blob.is_null() {
        return -(2 as libc::c_int);
    }
    if bitmap_to_string(bitmap, blob as *mut libc::c_void, len) != 0 as libc::c_int {
        free(blob as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    r = sshbuf_put_bignum2_bytes(buf, blob as *const libc::c_void, len);
    free(blob as *mut libc::c_void);
    return r;
}
unsafe extern "C" fn revoked_certs_generate(
    mut rc: *mut revoked_certs,
    mut buf: *mut sshbuf,
) -> libc::c_int {
    let mut current_block: u64;
    let mut final_0: libc::c_int = 0;
    let mut force_new_sect: libc::c_int = 0;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut i: u_int64_t = 0;
    let mut contig: u_int64_t = 0;
    let mut gap: u_int64_t = 0;
    let mut last: u_int64_t = 0 as libc::c_int as u_int64_t;
    let mut bitmap_start: u_int64_t = 0 as libc::c_int as u_int64_t;
    let mut rs: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut nrs: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut rki: *mut revoked_key_id = 0 as *mut revoked_key_id;
    let mut next_state: libc::c_int = 0;
    let mut state: libc::c_int = 0 as libc::c_int;
    let mut sect: *mut sshbuf = 0 as *mut sshbuf;
    let mut bitmap: *mut bitmap = 0 as *mut bitmap;
    sect = sshbuf_new();
    if sect.is_null() {
        return -(2 as libc::c_int);
    }
    if ((*rc).ca_key).is_null() {
        r = sshbuf_put_string(buf, 0 as *const libc::c_void, 0 as libc::c_int as size_t);
        if r != 0 as libc::c_int {
            current_block = 9009306676914022655;
        } else {
            current_block = 14523784380283086299;
        }
    } else {
        r = sshkey_puts((*rc).ca_key, buf);
        if r != 0 as libc::c_int {
            current_block = 9009306676914022655;
        } else {
            current_block = 14523784380283086299;
        }
    }
    match current_block {
        14523784380283086299 => {
            r = sshbuf_put_string(buf, 0 as *const libc::c_void, 0 as libc::c_int as size_t);
            if !(r != 0 as libc::c_int) {
                rs = revoked_serial_tree_RB_MINMAX(&mut (*rc).revoked_serials, -(1 as libc::c_int));
                's_49: loop {
                    if rs.is_null() {
                        current_block = 2989495919056355252;
                        break;
                    }
                    nrs = revoked_serial_tree_RB_NEXT(rs);
                    final_0 = (nrs == 0 as *mut libc::c_void as *mut revoked_serial) as libc::c_int;
                    gap = if nrs.is_null() {
                        0 as libc::c_int as libc::c_ulong
                    } else {
                        ((*nrs).lo).wrapping_sub((*rs).hi)
                    };
                    contig = (1 as libc::c_int as libc::c_ulong)
                        .wrapping_add(((*rs).hi).wrapping_sub((*rs).lo));
                    next_state = choose_next_state(
                        state,
                        contig,
                        final_0,
                        if state == 0 as libc::c_int {
                            0 as libc::c_int as libc::c_ulong
                        } else {
                            ((*rs).lo).wrapping_sub(last)
                        },
                        gap,
                        &mut force_new_sect,
                    );
                    if state != 0 as libc::c_int
                        && (force_new_sect != 0
                            || next_state != state
                            || state == 0x21 as libc::c_int)
                    {
                        match state {
                            34 => {
                                r = put_bitmap(sect, bitmap);
                                if r != 0 as libc::c_int {
                                    current_block = 9009306676914022655;
                                    break;
                                }
                                bitmap_free(bitmap);
                                bitmap = 0 as *mut bitmap;
                            }
                            32 | 33 | _ => {}
                        }
                        r = sshbuf_put_u8(buf, state as u_char);
                        if r != 0 as libc::c_int || {
                            r = sshbuf_put_stringb(buf, sect);
                            r != 0 as libc::c_int
                        } {
                            current_block = 9009306676914022655;
                            break;
                        }
                        sshbuf_reset(sect);
                    }
                    if next_state != state || force_new_sect != 0 {
                        state = next_state;
                        sshbuf_reset(sect);
                        match state {
                            34 => {
                                bitmap = bitmap_new();
                                if bitmap.is_null() {
                                    r = -(2 as libc::c_int);
                                    current_block = 9009306676914022655;
                                    break;
                                } else {
                                    bitmap_start = (*rs).lo;
                                    r = sshbuf_put_u64(sect, bitmap_start);
                                    if r != 0 as libc::c_int {
                                        current_block = 9009306676914022655;
                                        break;
                                    }
                                }
                            }
                            32 | 33 | _ => {}
                        }
                    }
                    match state {
                        32 => {
                            i = 0 as libc::c_int as u_int64_t;
                            while i < contig {
                                r = sshbuf_put_u64(sect, ((*rs).lo).wrapping_add(i));
                                if r != 0 as libc::c_int {
                                    current_block = 9009306676914022655;
                                    break 's_49;
                                }
                                i = i.wrapping_add(1);
                                i;
                            }
                        }
                        33 => {
                            r = sshbuf_put_u64(sect, (*rs).lo);
                            if r != 0 as libc::c_int || {
                                r = sshbuf_put_u64(sect, (*rs).hi);
                                r != 0 as libc::c_int
                            } {
                                current_block = 9009306676914022655;
                                break;
                            }
                        }
                        34 => {
                            if ((*rs).lo).wrapping_sub(bitmap_start)
                                > 2147483647 as libc::c_int as libc::c_ulong
                            {
                                crate::log::sshlog(
                                    b"krl.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                                        b"revoked_certs_generate\0",
                                    ))
                                    .as_ptr(),
                                    678 as libc::c_int,
                                    1 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"insane bitmap gap\0" as *const u8 as *const libc::c_char,
                                );
                                current_block = 9009306676914022655;
                                break;
                            } else {
                                i = 0 as libc::c_int as u_int64_t;
                                while i < contig {
                                    if bitmap_set_bit(
                                        bitmap,
                                        ((*rs).lo).wrapping_add(i).wrapping_sub(bitmap_start)
                                            as u_int,
                                    ) != 0 as libc::c_int
                                    {
                                        r = -(2 as libc::c_int);
                                        current_block = 9009306676914022655;
                                        break 's_49;
                                    } else {
                                        i = i.wrapping_add(1);
                                        i;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    last = (*rs).hi;
                    rs = revoked_serial_tree_RB_NEXT(rs);
                }
                match current_block {
                    9009306676914022655 => {}
                    _ => {
                        if state != 0 as libc::c_int {
                            match state {
                                34 => {
                                    r = put_bitmap(sect, bitmap);
                                    if r != 0 as libc::c_int {
                                        current_block = 9009306676914022655;
                                    } else {
                                        bitmap_free(bitmap);
                                        bitmap = 0 as *mut bitmap;
                                        current_block = 13763002826403452995;
                                    }
                                }
                                32 | 33 | _ => {
                                    current_block = 13763002826403452995;
                                }
                            }
                            match current_block {
                                9009306676914022655 => {}
                                _ => {
                                    r = sshbuf_put_u8(buf, state as u_char);
                                    if r != 0 as libc::c_int || {
                                        r = sshbuf_put_stringb(buf, sect);
                                        r != 0 as libc::c_int
                                    } {
                                        current_block = 9009306676914022655;
                                    } else {
                                        current_block = 16415152177862271243;
                                    }
                                }
                            }
                        } else {
                            current_block = 16415152177862271243;
                        }
                        match current_block {
                            9009306676914022655 => {}
                            _ => {
                                sshbuf_reset(sect);
                                rki = revoked_key_id_tree_RB_MINMAX(
                                    &mut (*rc).revoked_key_ids,
                                    -(1 as libc::c_int),
                                );
                                loop {
                                    if rki.is_null() {
                                        current_block = 2706659501864706830;
                                        break;
                                    }
                                    r = sshbuf_put_cstring(sect, (*rki).key_id);
                                    if r != 0 as libc::c_int {
                                        current_block = 9009306676914022655;
                                        break;
                                    }
                                    rki = revoked_key_id_tree_RB_NEXT(rki);
                                }
                                match current_block {
                                    9009306676914022655 => {}
                                    _ => {
                                        if sshbuf_len(sect) != 0 as libc::c_int as libc::c_ulong {
                                            r = sshbuf_put_u8(buf, 0x23 as libc::c_int as u_char);
                                            if r != 0 as libc::c_int || {
                                                r = sshbuf_put_stringb(buf, sect);
                                                r != 0 as libc::c_int
                                            } {
                                                current_block = 9009306676914022655;
                                            } else {
                                                current_block = 3580086814630675314;
                                            }
                                        } else {
                                            current_block = 3580086814630675314;
                                        }
                                        match current_block {
                                            9009306676914022655 => {}
                                            _ => {
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
    bitmap_free(bitmap);
    sshbuf_free(sect);
    return r;
}
pub unsafe extern "C" fn ssh_krl_to_blob(
    mut krl: *mut ssh_krl,
    mut buf: *mut sshbuf,
    mut sign_keys: *mut *mut sshkey,
    mut nsign_keys: u_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut rc: *mut revoked_certs = 0 as *mut revoked_certs;
    let mut rb: *mut revoked_blob = 0 as *mut revoked_blob;
    let mut sect: *mut sshbuf = 0 as *mut sshbuf;
    let mut sblob: *mut u_char = 0 as *mut u_char;
    let mut slen: size_t = 0;
    let mut i: size_t = 0;
    if (*krl).generated_date == 0 as libc::c_int as libc::c_ulong {
        (*krl).generated_date = time(0 as *mut time_t) as u_int64_t;
    }
    sect = sshbuf_new();
    if sect.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_put(
        buf,
        b"SSHKRL\n\0\0" as *const u8 as *const libc::c_char as *const libc::c_void,
        (::core::mem::size_of::<[libc::c_char; 9]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong),
    );
    if !(r != 0 as libc::c_int
        || {
            r = sshbuf_put_u32(buf, 1 as libc::c_int as u_int32_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(buf, (*krl).krl_version);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(buf, (*krl).generated_date);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_u64(buf, (*krl).flags);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_string(buf, 0 as *const libc::c_void, 0 as libc::c_int as size_t);
            r != 0 as libc::c_int
        }
        || {
            r = sshbuf_put_cstring(buf, (*krl).comment);
            r != 0 as libc::c_int
        })
    {
        rc = (*krl).revoked_certs.tqh_first;
        loop {
            if rc.is_null() {
                current_block = 7746791466490516765;
                break;
            }
            sshbuf_reset(sect);
            r = revoked_certs_generate(rc, sect);
            if r != 0 as libc::c_int {
                current_block = 14509089820662752219;
                break;
            }
            r = sshbuf_put_u8(buf, 1 as libc::c_int as u_char);
            if r != 0 as libc::c_int || {
                r = sshbuf_put_stringb(buf, sect);
                r != 0 as libc::c_int
            } {
                current_block = 14509089820662752219;
                break;
            }
            rc = (*rc).entry.tqe_next;
        }
        match current_block {
            14509089820662752219 => {}
            _ => {
                sshbuf_reset(sect);
                rb = revoked_blob_tree_RB_MINMAX(&mut (*krl).revoked_keys, -(1 as libc::c_int));
                loop {
                    if rb.is_null() {
                        current_block = 8831408221741692167;
                        break;
                    }
                    r = sshbuf_put_string(sect, (*rb).blob as *const libc::c_void, (*rb).len);
                    if r != 0 as libc::c_int {
                        current_block = 14509089820662752219;
                        break;
                    }
                    rb = revoked_blob_tree_RB_NEXT(rb);
                }
                match current_block {
                    14509089820662752219 => {}
                    _ => {
                        if sshbuf_len(sect) != 0 as libc::c_int as libc::c_ulong {
                            r = sshbuf_put_u8(buf, 2 as libc::c_int as u_char);
                            if r != 0 as libc::c_int || {
                                r = sshbuf_put_stringb(buf, sect);
                                r != 0 as libc::c_int
                            } {
                                current_block = 14509089820662752219;
                            } else {
                                current_block = 15904375183555213903;
                            }
                        } else {
                            current_block = 15904375183555213903;
                        }
                        match current_block {
                            14509089820662752219 => {}
                            _ => {
                                sshbuf_reset(sect);
                                rb = revoked_blob_tree_RB_MINMAX(
                                    &mut (*krl).revoked_sha1s,
                                    -(1 as libc::c_int),
                                );
                                loop {
                                    if rb.is_null() {
                                        current_block = 11307063007268554308;
                                        break;
                                    }
                                    r = sshbuf_put_string(
                                        sect,
                                        (*rb).blob as *const libc::c_void,
                                        (*rb).len,
                                    );
                                    if r != 0 as libc::c_int {
                                        current_block = 14509089820662752219;
                                        break;
                                    }
                                    rb = revoked_blob_tree_RB_NEXT(rb);
                                }
                                match current_block {
                                    14509089820662752219 => {}
                                    _ => {
                                        if sshbuf_len(sect) != 0 as libc::c_int as libc::c_ulong {
                                            r = sshbuf_put_u8(buf, 3 as libc::c_int as u_char);
                                            if r != 0 as libc::c_int || {
                                                r = sshbuf_put_stringb(buf, sect);
                                                r != 0 as libc::c_int
                                            } {
                                                current_block = 14509089820662752219;
                                            } else {
                                                current_block = 18386322304582297246;
                                            }
                                        } else {
                                            current_block = 18386322304582297246;
                                        }
                                        match current_block {
                                            14509089820662752219 => {}
                                            _ => {
                                                sshbuf_reset(sect);
                                                rb = revoked_blob_tree_RB_MINMAX(
                                                    &mut (*krl).revoked_sha256s,
                                                    -(1 as libc::c_int),
                                                );
                                                loop {
                                                    if rb.is_null() {
                                                        current_block = 8693738493027456495;
                                                        break;
                                                    }
                                                    r = sshbuf_put_string(
                                                        sect,
                                                        (*rb).blob as *const libc::c_void,
                                                        (*rb).len,
                                                    );
                                                    if r != 0 as libc::c_int {
                                                        current_block = 14509089820662752219;
                                                        break;
                                                    }
                                                    rb = revoked_blob_tree_RB_NEXT(rb);
                                                }
                                                match current_block {
                                                    14509089820662752219 => {}
                                                    _ => {
                                                        if sshbuf_len(sect)
                                                            != 0 as libc::c_int as libc::c_ulong
                                                        {
                                                            r = sshbuf_put_u8(
                                                                buf,
                                                                5 as libc::c_int as u_char,
                                                            );
                                                            if r != 0 as libc::c_int || {
                                                                r = sshbuf_put_stringb(buf, sect);
                                                                r != 0 as libc::c_int
                                                            } {
                                                                current_block =
                                                                    14509089820662752219;
                                                            } else {
                                                                current_block =
                                                                    17500079516916021833;
                                                            }
                                                        } else {
                                                            current_block = 17500079516916021833;
                                                        }
                                                        match current_block {
                                                            14509089820662752219 => {}
                                                            _ => {
                                                                i = 0 as libc::c_int as size_t;
                                                                loop {
                                                                    if !(i < nsign_keys
                                                                        as libc::c_ulong)
                                                                    {
                                                                        current_block =
                                                                            11743904203796629665;
                                                                        break;
                                                                    }
                                                                    r = sshbuf_put_u8(
                                                                        buf,
                                                                        4 as libc::c_int as u_char,
                                                                    );
                                                                    if r != 0 as libc::c_int || {
                                                                        r = sshkey_puts(
                                                                            *sign_keys
                                                                                .offset(i as isize),
                                                                            buf,
                                                                        );
                                                                        r != 0 as libc::c_int
                                                                    } {
                                                                        current_block =
                                                                            14509089820662752219;
                                                                        break;
                                                                    }
                                                                    r = sshkey_sign(
                                                                        *sign_keys
                                                                            .offset(i as isize),
                                                                        &mut sblob,
                                                                        &mut slen,
                                                                        sshbuf_ptr(buf),
                                                                        sshbuf_len(buf),
                                                                        0 as *const libc::c_char,
                                                                        0 as *const libc::c_char,
                                                                        0 as *const libc::c_char,
                                                                        0 as libc::c_int as u_int,
                                                                    );
                                                                    if r != 0 as libc::c_int {
                                                                        current_block =
                                                                            14509089820662752219;
                                                                        break;
                                                                    }
                                                                    r = sshbuf_put_string(
                                                                        buf,
                                                                        sblob
                                                                            as *const libc::c_void,
                                                                        slen,
                                                                    );
                                                                    if r != 0 as libc::c_int {
                                                                        current_block =
                                                                            14509089820662752219;
                                                                        break;
                                                                    }
                                                                    i = i.wrapping_add(1);
                                                                    i;
                                                                }
                                                                match current_block {
                                                                    14509089820662752219 => {}
                                                                    _ => {
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
                            }
                        }
                    }
                }
            }
        }
    }
    free(sblob as *mut libc::c_void);
    sshbuf_free(sect);
    return r;
}
unsafe extern "C" fn format_timestamp(
    mut timestamp: u_int64_t,
    mut ts: *mut libc::c_char,
    mut nts: size_t,
) {
    let mut t: time_t = 0;
    let mut tm: *mut tm = 0 as *mut tm;
    t = timestamp as time_t;
    tm = localtime(&mut t);
    if tm.is_null() {
        strlcpy(ts, b"<INVALID>\0" as *const u8 as *const libc::c_char, nts);
    } else {
        *ts = '\0' as i32 as libc::c_char;
        strftime(
            ts,
            nts,
            b"%Y%m%dT%H%M%S\0" as *const u8 as *const libc::c_char,
            tm,
        );
    };
}
unsafe extern "C" fn parse_revoked_certs(
    mut buf: *mut sshbuf,
    mut krl: *mut ssh_krl,
) -> libc::c_int {
    let mut current_block: u64;
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut type_0: u_char = 0;
    let mut blob: *const u_char = 0 as *const u_char;
    let mut blen: size_t = 0;
    let mut nbits: size_t = 0;
    let mut subsect: *mut sshbuf = 0 as *mut sshbuf;
    let mut serial: u_int64_t = 0;
    let mut serial_lo: u_int64_t = 0;
    let mut serial_hi: u_int64_t = 0;
    let mut bitmap: *mut bitmap = 0 as *mut bitmap;
    let mut key_id: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut ca_key: *mut sshkey = 0 as *mut sshkey;
    subsect = sshbuf_new();
    if subsect.is_null() {
        return -(2 as libc::c_int);
    }
    r = sshbuf_get_string_direct(buf, &mut blob, &mut blen);
    if !(r != 0 as libc::c_int || {
        r = sshbuf_get_string_direct(buf, 0 as *mut *const u_char, 0 as *mut size_t);
        r != 0 as libc::c_int
    }) {
        if !(blen != 0 as libc::c_int as libc::c_ulong && {
            r = sshkey_from_blob(blob, blen, &mut ca_key);
            r != 0 as libc::c_int
        }) {
            's_36: loop {
                if !(sshbuf_len(buf) > 0 as libc::c_int as libc::c_ulong) {
                    current_block = 1356832168064818221;
                    break;
                }
                sshbuf_free(subsect);
                subsect = 0 as *mut sshbuf;
                r = sshbuf_get_u8(buf, &mut type_0);
                if r != 0 as libc::c_int || {
                    r = sshbuf_froms(buf, &mut subsect);
                    r != 0 as libc::c_int
                } {
                    current_block = 5485510540846724406;
                    break;
                }
                match type_0 as libc::c_int {
                    32 => {
                        while sshbuf_len(subsect) > 0 as libc::c_int as libc::c_ulong {
                            r = sshbuf_get_u64(subsect, &mut serial);
                            if r != 0 as libc::c_int {
                                current_block = 5485510540846724406;
                                break 's_36;
                            }
                            r = ssh_krl_revoke_cert_by_serial(krl, ca_key, serial);
                            if r != 0 as libc::c_int {
                                current_block = 5485510540846724406;
                                break 's_36;
                            }
                        }
                    }
                    33 => {
                        r = sshbuf_get_u64(subsect, &mut serial_lo);
                        if r != 0 as libc::c_int || {
                            r = sshbuf_get_u64(subsect, &mut serial_hi);
                            r != 0 as libc::c_int
                        } {
                            current_block = 5485510540846724406;
                            break;
                        }
                        r = ssh_krl_revoke_cert_by_serial_range(krl, ca_key, serial_lo, serial_hi);
                        if r != 0 as libc::c_int {
                            current_block = 5485510540846724406;
                            break;
                        }
                    }
                    34 => {
                        bitmap = bitmap_new();
                        if bitmap.is_null() {
                            r = -(2 as libc::c_int);
                            current_block = 5485510540846724406;
                            break;
                        } else {
                            r = sshbuf_get_u64(subsect, &mut serial_lo);
                            if r != 0 as libc::c_int || {
                                r = sshbuf_get_bignum2_bytes_direct(subsect, &mut blob, &mut blen);
                                r != 0 as libc::c_int
                            } {
                                current_block = 5485510540846724406;
                                break;
                            }
                            if bitmap_from_string(bitmap, blob as *const libc::c_void, blen)
                                != 0 as libc::c_int
                            {
                                r = -(4 as libc::c_int);
                                current_block = 5485510540846724406;
                                break;
                            } else {
                                nbits = bitmap_nbits(bitmap);
                                serial = 0 as libc::c_int as u_int64_t;
                                while serial < nbits {
                                    if serial > 0 as libc::c_int as libc::c_ulong
                                        && serial_lo.wrapping_add(serial)
                                            == 0 as libc::c_int as libc::c_ulong
                                    {
                                        crate::log::sshlog(
                                            b"krl.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 20],
                                                &[libc::c_char; 20],
                                            >(
                                                b"parse_revoked_certs\0"
                                            ))
                                            .as_ptr(),
                                            909 as libc::c_int,
                                            1 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"bitmap wraps u64\0" as *const u8
                                                as *const libc::c_char,
                                        );
                                        r = -(4 as libc::c_int);
                                        current_block = 5485510540846724406;
                                        break 's_36;
                                    } else {
                                        if !(bitmap_test_bit(bitmap, serial as u_int) == 0) {
                                            r = ssh_krl_revoke_cert_by_serial(
                                                krl,
                                                ca_key,
                                                serial_lo.wrapping_add(serial),
                                            );
                                            if r != 0 as libc::c_int {
                                                current_block = 5485510540846724406;
                                                break 's_36;
                                            }
                                        }
                                        serial = serial.wrapping_add(1);
                                        serial;
                                    }
                                }
                                bitmap_free(bitmap);
                                bitmap = 0 as *mut bitmap;
                            }
                        }
                    }
                    35 => {
                        while sshbuf_len(subsect) > 0 as libc::c_int as libc::c_ulong {
                            r = sshbuf_get_cstring(subsect, &mut key_id, 0 as *mut size_t);
                            if r != 0 as libc::c_int {
                                current_block = 5485510540846724406;
                                break 's_36;
                            }
                            r = ssh_krl_revoke_cert_by_key_id(krl, ca_key, key_id);
                            if r != 0 as libc::c_int {
                                current_block = 5485510540846724406;
                                break 's_36;
                            }
                            free(key_id as *mut libc::c_void);
                            key_id = 0 as *mut libc::c_char;
                        }
                    }
                    _ => {
                        crate::log::sshlog(
                            b"krl.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                                b"parse_revoked_certs\0",
                            ))
                            .as_ptr(),
                            935 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"Unsupported KRL certificate section %u\0" as *const u8
                                as *const libc::c_char,
                            type_0 as libc::c_int,
                        );
                        r = -(4 as libc::c_int);
                        current_block = 5485510540846724406;
                        break;
                    }
                }
                if !(sshbuf_len(subsect) > 0 as libc::c_int as libc::c_ulong) {
                    continue;
                }
                crate::log::sshlog(
                    b"krl.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"parse_revoked_certs\0",
                    ))
                    .as_ptr(),
                    940 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"KRL certificate section contains unparsed data\0" as *const u8
                        as *const libc::c_char,
                );
                r = -(4 as libc::c_int);
                current_block = 5485510540846724406;
                break;
            }
            match current_block {
                5485510540846724406 => {}
                _ => {
                    r = 0 as libc::c_int;
                }
            }
        }
    }
    if !bitmap.is_null() {
        bitmap_free(bitmap);
    }
    free(key_id as *mut libc::c_void);
    sshkey_free(ca_key);
    sshbuf_free(subsect);
    return r;
}
unsafe extern "C" fn blob_section(
    mut sect: *mut sshbuf,
    mut target_tree: *mut revoked_blob_tree,
    mut expected_len: size_t,
) -> libc::c_int {
    let mut rdata: *mut u_char = 0 as *mut u_char;
    let mut rlen: size_t = 0 as libc::c_int as size_t;
    let mut r: libc::c_int = 0;
    while sshbuf_len(sect) > 0 as libc::c_int as libc::c_ulong {
        r = sshbuf_get_string(sect, &mut rdata, &mut rlen);
        if r != 0 as libc::c_int {
            return r;
        }
        if expected_len != 0 as libc::c_int as libc::c_ulong && rlen != expected_len {
            crate::log::sshlog(
                b"krl.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"blob_section\0"))
                    .as_ptr(),
                968 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"bad length\0" as *const u8 as *const libc::c_char,
            );
            free(rdata as *mut libc::c_void);
            return -(4 as libc::c_int);
        }
        r = revoke_blob(target_tree, rdata, rlen);
        if r != 0 as libc::c_int {
            free(rdata as *mut libc::c_void);
            return r;
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_krl_from_blob(
    mut buf: *mut sshbuf,
    mut krlp: *mut *mut ssh_krl,
    mut sign_ca_keys: *mut *const sshkey,
    mut nsign_ca_keys: size_t,
) -> libc::c_int {
    let mut current_block: u64;
    let mut copy: *mut sshbuf = 0 as *mut sshbuf;
    let mut sect: *mut sshbuf = 0 as *mut sshbuf;
    let mut krl: *mut ssh_krl = 0 as *mut ssh_krl;
    let mut timestamp: [libc::c_char; 64] = [0; 64];
    let mut r: libc::c_int = -(1 as libc::c_int);
    let mut sig_seen: libc::c_int = 0;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut ca_used: *mut *mut sshkey = 0 as *mut *mut sshkey;
    let mut tmp_ca_used: *mut *mut sshkey = 0 as *mut *mut sshkey;
    let mut type_0: u_char = 0;
    let mut blob: *const u_char = 0 as *const u_char;
    let mut i: size_t = 0;
    let mut j: size_t = 0;
    let mut sig_off: size_t = 0;
    let mut sects_off: size_t = 0;
    let mut blen: size_t = 0;
    let mut nca_used: size_t = 0;
    let mut format_version: u_int = 0;
    nca_used = 0 as libc::c_int as size_t;
    *krlp = 0 as *mut ssh_krl;
    if sshbuf_len(buf)
        < (::core::mem::size_of::<[libc::c_char; 9]>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        || memcmp(
            sshbuf_ptr(buf) as *const libc::c_void,
            b"SSHKRL\n\0\0" as *const u8 as *const libc::c_char as *const libc::c_void,
            (::core::mem::size_of::<[libc::c_char; 9]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        ) != 0 as libc::c_int
    {
        crate::log::sshlog(
            b"krl.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_krl_from_blob\0"))
                .as_ptr(),
            999 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG3,
            0 as *const libc::c_char,
            b"not a KRL\0" as *const u8 as *const libc::c_char,
        );
        return -(50 as libc::c_int);
    }
    copy = sshbuf_fromb(buf);
    if copy.is_null() {
        r = -(2 as libc::c_int);
    } else {
        r = sshbuf_consume(
            copy,
            (::core::mem::size_of::<[libc::c_char; 9]>() as libc::c_ulong)
                .wrapping_sub(1 as libc::c_int as libc::c_ulong),
        );
        if !(r != 0 as libc::c_int) {
            krl = ssh_krl_init();
            if krl.is_null() {
                crate::log::sshlog(
                    b"krl.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"ssh_krl_from_blob\0",
                    ))
                    .as_ptr(),
                    1012 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"alloc failed\0" as *const u8 as *const libc::c_char,
                );
            } else {
                r = sshbuf_get_u32(copy, &mut format_version);
                if !(r != 0 as libc::c_int) {
                    if format_version != 1 as libc::c_int as libc::c_uint {
                        r = -(4 as libc::c_int);
                    } else {
                        r = sshbuf_get_u64(copy, &mut (*krl).krl_version);
                        if !(r != 0 as libc::c_int
                            || {
                                r = sshbuf_get_u64(copy, &mut (*krl).generated_date);
                                r != 0 as libc::c_int
                            }
                            || {
                                r = sshbuf_get_u64(copy, &mut (*krl).flags);
                                r != 0 as libc::c_int
                            }
                            || {
                                r = sshbuf_get_string_direct(
                                    copy,
                                    0 as *mut *const u_char,
                                    0 as *mut size_t,
                                );
                                r != 0 as libc::c_int
                            }
                            || {
                                r = sshbuf_get_cstring(copy, &mut (*krl).comment, 0 as *mut size_t);
                                r != 0 as libc::c_int
                            })
                        {
                            format_timestamp(
                                (*krl).generated_date,
                                timestamp.as_mut_ptr(),
                                ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
                            );
                            crate::log::sshlog(
                                b"krl.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                                    b"ssh_krl_from_blob\0",
                                ))
                                .as_ptr(),
                                1032 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG1,
                                0 as *const libc::c_char,
                                b"KRL version %llu generated at %s%s%s\0" as *const u8
                                    as *const libc::c_char,
                                (*krl).krl_version as libc::c_ulonglong,
                                timestamp.as_mut_ptr(),
                                if *(*krl).comment as libc::c_int != 0 {
                                    b": \0" as *const u8 as *const libc::c_char
                                } else {
                                    b"\0" as *const u8 as *const libc::c_char
                                },
                                (*krl).comment,
                            );
                            sig_seen = 0 as libc::c_int;
                            if sshbuf_len(buf) < sshbuf_len(copy) {
                                r = -(1 as libc::c_int);
                            } else {
                                sects_off = (sshbuf_len(buf)).wrapping_sub(sshbuf_len(copy));
                                's_105: loop {
                                    if !(sshbuf_len(copy) > 0 as libc::c_int as libc::c_ulong) {
                                        current_block = 6717214610478484138;
                                        break;
                                    }
                                    r = sshbuf_get_u8(copy, &mut type_0);
                                    if r != 0 as libc::c_int || {
                                        r = sshbuf_get_string_direct(copy, &mut blob, &mut blen);
                                        r != 0 as libc::c_int
                                    } {
                                        current_block = 6024365533601602204;
                                        break;
                                    }
                                    if type_0 as libc::c_int != 4 as libc::c_int {
                                        if !(sig_seen != 0) {
                                            continue;
                                        }
                                        crate::log::sshlog(
                                            b"krl.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 18],
                                                &[libc::c_char; 18],
                                            >(
                                                b"ssh_krl_from_blob\0"
                                            ))
                                            .as_ptr(),
                                            1053 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"KRL contains non-signature section after signature\0"
                                                as *const u8
                                                as *const libc::c_char,
                                        );
                                        r = -(4 as libc::c_int);
                                        current_block = 6024365533601602204;
                                        break;
                                    } else {
                                        sig_seen = 1 as libc::c_int;
                                        r = sshkey_from_blob(blob, blen, &mut key);
                                        if r != 0 as libc::c_int {
                                            r = -(4 as libc::c_int);
                                            current_block = 6024365533601602204;
                                            break;
                                        } else if sshbuf_len(buf) < sshbuf_len(copy) {
                                            r = -(1 as libc::c_int);
                                            current_block = 6024365533601602204;
                                            break;
                                        } else {
                                            sig_off =
                                                (sshbuf_len(buf)).wrapping_sub(sshbuf_len(copy));
                                            r = sshbuf_get_string_direct(
                                                copy, &mut blob, &mut blen,
                                            );
                                            if r != 0 as libc::c_int {
                                                r = -(4 as libc::c_int);
                                                current_block = 6024365533601602204;
                                                break;
                                            } else {
                                                r = sshkey_verify(
                                                    key,
                                                    blob,
                                                    blen,
                                                    sshbuf_ptr(buf),
                                                    sig_off,
                                                    0 as *const libc::c_char,
                                                    0 as libc::c_int as u_int,
                                                    0 as *mut *mut sshkey_sig_details,
                                                );
                                                if r != 0 as libc::c_int {
                                                    current_block = 6024365533601602204;
                                                    break;
                                                }
                                                i = 0 as libc::c_int as size_t;
                                                while i < nca_used {
                                                    if sshkey_equal(
                                                        *ca_used.offset(i as isize),
                                                        key,
                                                    ) != 0
                                                    {
                                                        crate::log::sshlog(
                                                            b"krl.c\0" as *const u8 as *const libc::c_char,
                                                            (*::core::mem::transmute::<
                                                                &[u8; 18],
                                                                &[libc::c_char; 18],
                                                            >(b"ssh_krl_from_blob\0"))
                                                                .as_ptr(),
                                                            1085 as libc::c_int,
                                                            0 as libc::c_int,
                                                            SYSLOG_LEVEL_ERROR,
                                                            0 as *const libc::c_char,
                                                            b"KRL signed more than once with the same key\0"
                                                                as *const u8 as *const libc::c_char,
                                                        );
                                                        r = -(4 as libc::c_int);
                                                        current_block = 6024365533601602204;
                                                        break 's_105;
                                                    } else {
                                                        i = i.wrapping_add(1);
                                                        i;
                                                    }
                                                }
                                                tmp_ca_used = recallocarray(
                                                    ca_used as *mut libc::c_void,
                                                    nca_used,
                                                    nca_used.wrapping_add(
                                                        1 as libc::c_int as libc::c_ulong,
                                                    ),
                                                    ::core::mem::size_of::<*mut sshkey>()
                                                        as libc::c_ulong,
                                                )
                                                    as *mut *mut sshkey;
                                                if tmp_ca_used.is_null() {
                                                    r = -(2 as libc::c_int);
                                                    current_block = 6024365533601602204;
                                                    break;
                                                } else {
                                                    ca_used = tmp_ca_used;
                                                    let fresh0 = nca_used;
                                                    nca_used = nca_used.wrapping_add(1);
                                                    let ref mut fresh1 =
                                                        *ca_used.offset(fresh0 as isize);
                                                    *fresh1 = key;
                                                    key = 0 as *mut sshkey;
                                                }
                                            }
                                        }
                                    }
                                }
                                match current_block {
                                    6024365533601602204 => {}
                                    _ => {
                                        if sshbuf_len(copy) != 0 as libc::c_int as libc::c_ulong {
                                            r = -(1 as libc::c_int);
                                        } else {
                                            sshbuf_free(copy);
                                            copy = sshbuf_fromb(buf);
                                            if copy.is_null() {
                                                r = -(2 as libc::c_int);
                                            } else {
                                                r = sshbuf_consume(copy, sects_off);
                                                if !(r != 0 as libc::c_int) {
                                                    loop {
                                                        if !(sshbuf_len(copy)
                                                            > 0 as libc::c_int as libc::c_ulong)
                                                        {
                                                            current_block = 5684854171168229155;
                                                            break;
                                                        }
                                                        sshbuf_free(sect);
                                                        sect = 0 as *mut sshbuf;
                                                        r = sshbuf_get_u8(copy, &mut type_0);
                                                        if r != 0 as libc::c_int || {
                                                            r = sshbuf_froms(copy, &mut sect);
                                                            r != 0 as libc::c_int
                                                        } {
                                                            current_block = 6024365533601602204;
                                                            break;
                                                        }
                                                        match type_0 as libc::c_int {
                                                            1 => {
                                                                r = parse_revoked_certs(sect, krl);
                                                                if r != 0 as libc::c_int {
                                                                    current_block =
                                                                        6024365533601602204;
                                                                    break;
                                                                }
                                                            }
                                                            2 => {
                                                                r = blob_section(
                                                                    sect,
                                                                    &mut (*krl).revoked_keys,
                                                                    0 as libc::c_int as size_t,
                                                                );
                                                                if r != 0 as libc::c_int {
                                                                    current_block =
                                                                        6024365533601602204;
                                                                    break;
                                                                }
                                                            }
                                                            3 => {
                                                                r = blob_section(
                                                                    sect,
                                                                    &mut (*krl).revoked_sha1s,
                                                                    20 as libc::c_int as size_t,
                                                                );
                                                                if r != 0 as libc::c_int {
                                                                    current_block =
                                                                        6024365533601602204;
                                                                    break;
                                                                }
                                                            }
                                                            5 => {
                                                                r = blob_section(
                                                                    sect,
                                                                    &mut (*krl).revoked_sha256s,
                                                                    32 as libc::c_int as size_t,
                                                                );
                                                                if r != 0 as libc::c_int {
                                                                    current_block =
                                                                        6024365533601602204;
                                                                    break;
                                                                }
                                                            }
                                                            4 => {
                                                                sshbuf_free(sect);
                                                                sect = 0 as *mut sshbuf;
                                                                r = sshbuf_get_string_direct(
                                                                    copy,
                                                                    0 as *mut *const u_char,
                                                                    0 as *mut size_t,
                                                                );
                                                                if r != 0 as libc::c_int {
                                                                    current_block =
                                                                        6024365533601602204;
                                                                    break;
                                                                }
                                                            }
                                                            _ => {
                                                                crate::log::sshlog(
                                                                    b"krl.c\0" as *const u8
                                                                        as *const libc::c_char,
                                                                    (*::core::mem::transmute::<
                                                                        &[u8; 18],
                                                                        &[libc::c_char; 18],
                                                                    >(
                                                                        b"ssh_krl_from_blob\0"
                                                                    ))
                                                                    .as_ptr(),
                                                                    1155 as libc::c_int,
                                                                    0 as libc::c_int,
                                                                    SYSLOG_LEVEL_ERROR,
                                                                    0 as *const libc::c_char,
                                                                    b"Unsupported KRL section %u\0"
                                                                        as *const u8
                                                                        as *const libc::c_char,
                                                                    type_0 as libc::c_int,
                                                                );
                                                                r = -(4 as libc::c_int);
                                                                current_block = 6024365533601602204;
                                                                break;
                                                            }
                                                        }
                                                        if !(!sect.is_null()
                                                            && sshbuf_len(sect)
                                                                > 0 as libc::c_int as libc::c_ulong)
                                                        {
                                                            continue;
                                                        }
                                                        crate::log::sshlog(
                                                            b"krl.c\0" as *const u8
                                                                as *const libc::c_char,
                                                            (*::core::mem::transmute::<
                                                                &[u8; 18],
                                                                &[libc::c_char; 18],
                                                            >(
                                                                b"ssh_krl_from_blob\0"
                                                            ))
                                                            .as_ptr(),
                                                            1160 as libc::c_int,
                                                            0 as libc::c_int,
                                                            SYSLOG_LEVEL_ERROR,
                                                            0 as *const libc::c_char,
                                                            b"KRL section contains unparsed data\0"
                                                                as *const u8
                                                                as *const libc::c_char,
                                                        );
                                                        r = -(4 as libc::c_int);
                                                        current_block = 6024365533601602204;
                                                        break;
                                                    }
                                                    match current_block {
                                                        6024365533601602204 => {}
                                                        _ => {
                                                            sig_seen = 0 as libc::c_int;
                                                            i = 0 as libc::c_int as size_t;
                                                            while i < nca_used {
                                                                if ssh_krl_check_key(
                                                                    krl,
                                                                    *ca_used.offset(i as isize),
                                                                ) == 0 as libc::c_int
                                                                {
                                                                    sig_seen = 1 as libc::c_int;
                                                                } else {
                                                                    sshkey_free(
                                                                        *ca_used.offset(i as isize),
                                                                    );
                                                                    let ref mut fresh2 =
                                                                        *ca_used.offset(i as isize);
                                                                    *fresh2 = 0 as *mut sshkey;
                                                                }
                                                                i = i.wrapping_add(1);
                                                                i;
                                                            }
                                                            if nca_used != 0 && sig_seen == 0 {
                                                                crate::log::sshlog(
                                                                    b"krl.c\0" as *const u8 as *const libc::c_char,
                                                                    (*::core::mem::transmute::<
                                                                        &[u8; 18],
                                                                        &[libc::c_char; 18],
                                                                    >(b"ssh_krl_from_blob\0"))
                                                                        .as_ptr(),
                                                                    1177 as libc::c_int,
                                                                    0 as libc::c_int,
                                                                    SYSLOG_LEVEL_ERROR,
                                                                    0 as *const libc::c_char,
                                                                    b"All keys used to sign KRL were revoked\0" as *const u8
                                                                        as *const libc::c_char,
                                                                );
                                                                r = -(51 as libc::c_int);
                                                            } else {
                                                                if sig_seen != 0
                                                                    && nsign_ca_keys
                                                                        != 0 as libc::c_int
                                                                            as libc::c_ulong
                                                                {
                                                                    sig_seen = 0 as libc::c_int;
                                                                    i = 0 as libc::c_int as size_t;
                                                                    while sig_seen == 0
                                                                        && i < nsign_ca_keys
                                                                    {
                                                                        j = 0 as libc::c_int
                                                                            as size_t;
                                                                        while j < nca_used {
                                                                            if !(*ca_used
                                                                                .offset(j as isize))
                                                                            .is_null()
                                                                            {
                                                                                if sshkey_equal(
                                                                                    *ca_used
                                                                                        .offset(
                                                                                        j as isize,
                                                                                    ),
                                                                                    *sign_ca_keys
                                                                                        .offset(
                                                                                        i as isize,
                                                                                    ),
                                                                                ) != 0
                                                                                {
                                                                                    sig_seen = 1 as libc::c_int;
                                                                                    break;
                                                                                }
                                                                            }
                                                                            j = j.wrapping_add(1);
                                                                            j;
                                                                        }
                                                                        i = i.wrapping_add(1);
                                                                        i;
                                                                    }
                                                                    if sig_seen == 0 {
                                                                        r = -(21 as libc::c_int);
                                                                        crate::log::sshlog(
                                                                            b"krl.c\0" as *const u8 as *const libc::c_char,
                                                                            (*::core::mem::transmute::<
                                                                                &[u8; 18],
                                                                                &[libc::c_char; 18],
                                                                            >(b"ssh_krl_from_blob\0"))
                                                                                .as_ptr(),
                                                                            1197 as libc::c_int,
                                                                            0 as libc::c_int,
                                                                            SYSLOG_LEVEL_ERROR,
                                                                            0 as *const libc::c_char,
                                                                            b"KRL not signed with any trusted key\0" as *const u8
                                                                                as *const libc::c_char,
                                                                        );
                                                                        current_block =
                                                                            6024365533601602204;
                                                                    } else {
                                                                        current_block =
                                                                            6014157347423944569;
                                                                    }
                                                                } else {
                                                                    current_block =
                                                                        6014157347423944569;
                                                                }
                                                                match current_block {
                                                                    6024365533601602204 => {}
                                                                    _ => {
                                                                        *krlp = krl;
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
                            }
                        }
                    }
                }
            }
        }
    }
    if r != 0 as libc::c_int {
        ssh_krl_free(krl);
    }
    i = 0 as libc::c_int as size_t;
    while i < nca_used {
        sshkey_free(*ca_used.offset(i as isize));
        i = i.wrapping_add(1);
        i;
    }
    free(ca_used as *mut libc::c_void);
    sshkey_free(key);
    sshbuf_free(copy);
    sshbuf_free(sect);
    return r;
}
unsafe extern "C" fn is_cert_revoked(
    mut key: *const sshkey,
    mut rc: *mut revoked_certs,
) -> libc::c_int {
    let mut rs: revoked_serial = revoked_serial {
        lo: 0,
        hi: 0,
        tree_entry: C2RustUnnamed_1 {
            rbe_left: 0 as *mut revoked_serial,
            rbe_right: 0 as *mut revoked_serial,
            rbe_parent: 0 as *mut revoked_serial,
            rbe_color: 0,
        },
    };
    let mut ers: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut rki: revoked_key_id = revoked_key_id {
        key_id: 0 as *mut libc::c_char,
        tree_entry: C2RustUnnamed_0 {
            rbe_left: 0 as *mut revoked_key_id,
            rbe_right: 0 as *mut revoked_key_id,
            rbe_parent: 0 as *mut revoked_key_id,
            rbe_color: 0,
        },
    };
    let mut erki: *mut revoked_key_id = 0 as *mut revoked_key_id;
    memset(
        &mut rki as *mut revoked_key_id as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<revoked_key_id>() as libc::c_ulong,
    );
    rki.key_id = (*(*key).cert).key_id;
    erki = revoked_key_id_tree_RB_FIND(&mut (*rc).revoked_key_ids, &mut rki);
    if !erki.is_null() {
        return -(51 as libc::c_int);
    }
    if (*(*key).cert).serial == 0 as libc::c_int as libc::c_ulong {
        return 0 as libc::c_int;
    }
    memset(
        &mut rs as *mut revoked_serial as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<revoked_serial>() as libc::c_ulong,
    );
    rs.hi = (*(*key).cert).serial;
    rs.lo = rs.hi;
    ers = revoked_serial_tree_RB_FIND(&mut (*rc).revoked_serials, &mut rs);
    if !ers.is_null() {
        return -(51 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn is_key_revoked(mut krl: *mut ssh_krl, mut key: *const sshkey) -> libc::c_int {
    let mut rb: revoked_blob = revoked_blob {
        blob: 0 as *mut u_char,
        len: 0,
        tree_entry: C2RustUnnamed_2 {
            rbe_left: 0 as *mut revoked_blob,
            rbe_right: 0 as *mut revoked_blob,
            rbe_parent: 0 as *mut revoked_blob,
            rbe_color: 0,
        },
    };
    let mut erb: *mut revoked_blob = 0 as *mut revoked_blob;
    let mut rc: *mut revoked_certs = 0 as *mut revoked_certs;
    let mut r: libc::c_int = 0;
    memset(
        &mut rb as *mut revoked_blob as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<revoked_blob>() as libc::c_ulong,
    );
    r = sshkey_fingerprint_raw(key, 1 as libc::c_int, &mut rb.blob, &mut rb.len);
    if r != 0 as libc::c_int {
        return r;
    }
    erb = revoked_blob_tree_RB_FIND(&mut (*krl).revoked_sha1s, &mut rb);
    free(rb.blob as *mut libc::c_void);
    if !erb.is_null() {
        return -(51 as libc::c_int);
    }
    memset(
        &mut rb as *mut revoked_blob as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<revoked_blob>() as libc::c_ulong,
    );
    r = sshkey_fingerprint_raw(key, 2 as libc::c_int, &mut rb.blob, &mut rb.len);
    if r != 0 as libc::c_int {
        return r;
    }
    erb = revoked_blob_tree_RB_FIND(&mut (*krl).revoked_sha256s, &mut rb);
    free(rb.blob as *mut libc::c_void);
    if !erb.is_null() {
        return -(51 as libc::c_int);
    }
    memset(
        &mut rb as *mut revoked_blob as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<revoked_blob>() as libc::c_ulong,
    );
    r = plain_key_blob(key, &mut rb.blob, &mut rb.len);
    if r != 0 as libc::c_int {
        return r;
    }
    erb = revoked_blob_tree_RB_FIND(&mut (*krl).revoked_keys, &mut rb);
    free(rb.blob as *mut libc::c_void);
    if !erb.is_null() {
        return -(51 as libc::c_int);
    }
    if sshkey_is_cert(key) == 0 {
        return 0 as libc::c_int;
    }
    r = revoked_certs_for_ca_key(krl, (*(*key).cert).signature_key, &mut rc, 0 as libc::c_int);
    if r != 0 as libc::c_int {
        return r;
    }
    if !rc.is_null() {
        r = is_cert_revoked(key, rc);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    r = revoked_certs_for_ca_key(krl, 0 as *const sshkey, &mut rc, 0 as libc::c_int);
    if r != 0 as libc::c_int {
        return r;
    }
    if !rc.is_null() {
        r = is_cert_revoked(key, rc);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_krl_check_key(
    mut krl: *mut ssh_krl,
    mut key: *const sshkey,
) -> libc::c_int {
    let mut r: libc::c_int = 0;
    r = is_key_revoked(krl, key);
    if r != 0 as libc::c_int {
        return r;
    }
    if sshkey_is_cert(key) != 0 {
        crate::log::sshlog(
            b"krl.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"ssh_krl_check_key\0"))
                .as_ptr(),
            1323 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG2,
            0 as *const libc::c_char,
            b"checking CA key\0" as *const u8 as *const libc::c_char,
        );
        r = is_key_revoked(krl, (*(*key).cert).signature_key);
        if r != 0 as libc::c_int {
            return r;
        }
    }
    return 0 as libc::c_int;
}
pub unsafe extern "C" fn ssh_krl_file_contains_key(
    mut path: *const libc::c_char,
    mut key: *const sshkey,
) -> libc::c_int {
    let mut krlbuf: *mut sshbuf = 0 as *mut sshbuf;
    let mut krl: *mut ssh_krl = 0 as *mut ssh_krl;
    let mut oerrno: libc::c_int = 0 as libc::c_int;
    let mut r: libc::c_int = 0;
    if path.is_null() {
        return 0 as libc::c_int;
    }
    r = sshbuf_load_file(path, &mut krlbuf);
    if r != 0 as libc::c_int {
        oerrno = *__errno_location();
    } else {
        r = ssh_krl_from_blob(
            krlbuf,
            &mut krl,
            0 as *mut *const sshkey,
            0 as libc::c_int as size_t,
        );
        if !(r != 0 as libc::c_int) {
            crate::log::sshlog(
                b"krl.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"ssh_krl_file_contains_key\0",
                ))
                .as_ptr(),
                1346 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG2,
                0 as *const libc::c_char,
                b"checking KRL %s\0" as *const u8 as *const libc::c_char,
                path,
            );
            r = ssh_krl_check_key(krl, key);
        }
    }
    sshbuf_free(krlbuf);
    ssh_krl_free(krl);
    if r != 0 as libc::c_int {
        *__errno_location() = oerrno;
    }
    return r;
}
pub unsafe extern "C" fn krl_dump(mut krl: *mut ssh_krl, mut f: *mut libc::FILE) -> libc::c_int {
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut rb: *mut revoked_blob = 0 as *mut revoked_blob;
    let mut rc: *mut revoked_certs = 0 as *mut revoked_certs;
    let mut rs: *mut revoked_serial = 0 as *mut revoked_serial;
    let mut rki: *mut revoked_key_id = 0 as *mut revoked_key_id;
    let mut r: libc::c_int = 0;
    let mut ret: libc::c_int = 0 as libc::c_int;
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut timestamp: [libc::c_char; 64] = [0; 64];
    format_timestamp(
        (*krl).generated_date,
        timestamp.as_mut_ptr(),
        ::core::mem::size_of::<[libc::c_char; 64]>() as libc::c_ulong,
    );
    fprintf(
        f,
        b"# KRL version %llu\n\0" as *const u8 as *const libc::c_char,
        (*krl).krl_version as libc::c_ulonglong,
    );
    fprintf(
        f,
        b"# Generated at %s\n\0" as *const u8 as *const libc::c_char,
        timestamp.as_mut_ptr(),
    );
    if !((*krl).comment).is_null() && *(*krl).comment as libc::c_int != '\0' as i32 {
        r = 2147483647 as libc::c_int;
        asmprintf(
            &mut fp as *mut *mut libc::c_char,
            2147483647 as libc::c_int as size_t,
            &mut r as *mut libc::c_int,
            b"%s\0" as *const u8 as *const libc::c_char,
            (*krl).comment,
        );
        fprintf(
            f,
            b"# Comment: %s\n\0" as *const u8 as *const libc::c_char,
            fp,
        );
        free(fp as *mut libc::c_void);
    }
    fputc('\n' as i32, f);
    rb = revoked_blob_tree_RB_MINMAX(&mut (*krl).revoked_keys, -(1 as libc::c_int));
    while !rb.is_null() {
        r = sshkey_from_blob((*rb).blob, (*rb).len, &mut key);
        if r != 0 as libc::c_int {
            ret = -(4 as libc::c_int);
            crate::log::sshlog(
                b"krl.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"krl_dump\0")).as_ptr(),
                1383 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                ssh_err(r),
                b"parse KRL key\0" as *const u8 as *const libc::c_char,
            );
        } else {
            fp = sshkey_fingerprint(key, 2 as libc::c_int, SSH_FP_DEFAULT);
            if fp.is_null() {
                ret = -(4 as libc::c_int);
                crate::log::sshlog(
                    b"krl.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"krl_dump\0"))
                        .as_ptr(),
                    1389 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
                );
            } else {
                fprintf(
                    f,
                    b"hash: %s # %s\n\0" as *const u8 as *const libc::c_char,
                    fp,
                    sshkey_ssh_name(key),
                );
                free(fp as *mut libc::c_void);
                free(key as *mut libc::c_void);
            }
        }
        rb = revoked_blob_tree_RB_NEXT(rb);
    }
    rb = revoked_blob_tree_RB_MINMAX(&mut (*krl).revoked_sha256s, -(1 as libc::c_int));
    while !rb.is_null() {
        fp = tohex((*rb).blob as *const libc::c_void, (*rb).len);
        fprintf(
            f,
            b"hash: SHA256:%s\n\0" as *const u8 as *const libc::c_char,
            fp,
        );
        free(fp as *mut libc::c_void);
        rb = revoked_blob_tree_RB_NEXT(rb);
    }
    rb = revoked_blob_tree_RB_MINMAX(&mut (*krl).revoked_sha1s, -(1 as libc::c_int));
    while !rb.is_null() {
        fp = tohex((*rb).blob as *const libc::c_void, (*rb).len);
        fprintf(
            f,
            b"# hash SHA1:%s\n\0" as *const u8 as *const libc::c_char,
            fp,
        );
        free(fp as *mut libc::c_void);
        rb = revoked_blob_tree_RB_NEXT(rb);
    }
    let mut current_block_52: u64;
    rc = (*krl).revoked_certs.tqh_first;
    while !rc.is_null() {
        fputc('\n' as i32, f);
        if ((*rc).ca_key).is_null() {
            fprintf(f, b"# Wildcard CA\n\0" as *const u8 as *const libc::c_char);
            current_block_52 = 8180496224585318153;
        } else {
            fp = sshkey_fingerprint((*rc).ca_key, 2 as libc::c_int, SSH_FP_DEFAULT);
            if fp.is_null() {
                ret = -(4 as libc::c_int);
                crate::log::sshlog(
                    b"krl.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"krl_dump\0"))
                        .as_ptr(),
                    1419 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
                );
                current_block_52 = 4761528863920922185;
            } else {
                fprintf(
                    f,
                    b"# CA key %s %s\n\0" as *const u8 as *const libc::c_char,
                    sshkey_ssh_name((*rc).ca_key),
                    fp,
                );
                free(fp as *mut libc::c_void);
                current_block_52 = 8180496224585318153;
            }
        }
        match current_block_52 {
            8180496224585318153 => {
                rs = revoked_serial_tree_RB_MINMAX(&mut (*rc).revoked_serials, -(1 as libc::c_int));
                while !rs.is_null() {
                    if (*rs).lo == (*rs).hi {
                        fprintf(
                            f,
                            b"serial: %llu\n\0" as *const u8 as *const libc::c_char,
                            (*rs).lo as libc::c_ulonglong,
                        );
                    } else {
                        fprintf(
                            f,
                            b"serial: %llu-%llu\n\0" as *const u8 as *const libc::c_char,
                            (*rs).lo as libc::c_ulonglong,
                            (*rs).hi as libc::c_ulonglong,
                        );
                    }
                    rs = revoked_serial_tree_RB_NEXT(rs);
                }
                rki =
                    revoked_key_id_tree_RB_MINMAX(&mut (*rc).revoked_key_ids, -(1 as libc::c_int));
                while !rki.is_null() {
                    r = 2147483647 as libc::c_int;
                    asmprintf(
                        &mut fp as *mut *mut libc::c_char,
                        2147483647 as libc::c_int as size_t,
                        &mut r as *mut libc::c_int,
                        b"%s\0" as *const u8 as *const libc::c_char,
                        (*rki).key_id,
                    );
                    fprintf(f, b"id: %s\n\0" as *const u8 as *const libc::c_char, fp);
                    free(fp as *mut libc::c_void);
                    rki = revoked_key_id_tree_RB_NEXT(rki);
                }
            }
            _ => {}
        }
        rc = (*rc).entry.tqe_next;
    }
    return ret;
}
