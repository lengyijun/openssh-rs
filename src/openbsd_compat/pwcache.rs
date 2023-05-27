use ::libc;
extern "C" {
    fn getpwuid(__uid: __uid_t) -> *mut passwd;

    fn getgrgid(__gid: __gid_t) -> *mut group;
    fn free(_: *mut libc::c_void);
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
}
pub type __u_long = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type u_long = __u_long;
pub type gid_t = __gid_t;
pub type uid_t = __uid_t;
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
pub struct ncache {
    pub uid: uid_t,
    pub name: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ncache_0 {
    pub gid: gid_t,
    pub name: *mut libc::c_char,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct group {
    pub gr_name: *mut libc::c_char,
    pub gr_passwd: *mut libc::c_char,
    pub gr_gid: __gid_t,
    pub gr_mem: *mut *mut libc::c_char,
}
#[no_mangle]
pub unsafe extern "C" fn user_from_uid(
    mut uid: uid_t,
    mut nouser: libc::c_int,
) -> *mut libc::c_char {
    static mut c_uid: [ncache; 64] = [ncache {
        uid: 0,
        name: 0 as *const libc::c_char as *mut libc::c_char,
    }; 64];
    static mut pwopen: libc::c_int = 0;
    static mut nbuf: [libc::c_char; 15] = [0; 15];
    let mut pw: *mut passwd = 0 as *mut passwd;
    let mut cp: *mut ncache = 0 as *mut ncache;
    cp = c_uid
        .as_mut_ptr()
        .offset((uid & (64 as libc::c_int - 1 as libc::c_int) as libc::c_uint) as isize);
    if (*cp).uid != uid || ((*cp).name).is_null() {
        if pwopen == 0 as libc::c_int {
            pwopen = 1 as libc::c_int;
        }
        pw = getpwuid(uid);
        if pw.is_null() {
            if nouser != 0 {
                return 0 as *mut libc::c_char;
            }
            libc::snprintf(
                nbuf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 15]>() as usize,
                b"%lu\0" as *const u8 as *const libc::c_char,
                uid as u_long,
            );
        }
        (*cp).uid = uid;
        if !((*cp).name).is_null() {
            free((*cp).name as *mut libc::c_void);
        }
        (*cp).name = strdup(if !pw.is_null() {
            (*pw).pw_name
        } else {
            nbuf.as_mut_ptr()
        });
    }
    return (*cp).name;
}
#[no_mangle]
pub unsafe extern "C" fn group_from_gid(
    mut gid: gid_t,
    mut nogroup: libc::c_int,
) -> *mut libc::c_char {
    static mut c_gid: [ncache_0; 64] = [ncache_0 {
        gid: 0,
        name: 0 as *const libc::c_char as *mut libc::c_char,
    }; 64];
    static mut gropen: libc::c_int = 0;
    static mut nbuf: [libc::c_char; 15] = [0; 15];
    let mut gr: *mut group = 0 as *mut group;
    let mut cp: *mut ncache_0 = 0 as *mut ncache_0;
    cp = c_gid
        .as_mut_ptr()
        .offset((gid & (64 as libc::c_int - 1 as libc::c_int) as libc::c_uint) as isize);
    if (*cp).gid != gid || ((*cp).name).is_null() {
        if gropen == 0 as libc::c_int {
            gropen = 1 as libc::c_int;
        }
        gr = getgrgid(gid);
        if gr.is_null() {
            if nogroup != 0 {
                return 0 as *mut libc::c_char;
            }
            libc::snprintf(
                nbuf.as_mut_ptr(),
                ::core::mem::size_of::<[libc::c_char; 15]>() as usize,
                b"%lu\0" as *const u8 as *const libc::c_char,
                gid as u_long,
            );
        }
        (*cp).gid = gid;
        if !((*cp).name).is_null() {
            free((*cp).name as *mut libc::c_void);
        }
        (*cp).name = strdup(if !gr.is_null() {
            (*gr).gr_name
        } else {
            nbuf.as_mut_ptr()
        });
    }
    return (*cp).name;
}
