use ::libc;
extern "C" {
    fn setpwent();
    fn endpwent();
    fn getpwent() -> *mut passwd;
    fn crypt(__key: *const libc::c_char, __salt: *const libc::c_char) -> *mut libc::c_char;
    fn strlcpy(dst: *mut libc::c_char, src: *const libc::c_char, siz: size_t) -> size_t;
    fn strrchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn explicit_bzero(__s: *mut libc::c_void, __n: size_t);
    fn getspnam(__name: *const libc::c_char) -> *mut spwd;
}
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type size_t = libc::c_ulong;
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
pub struct spwd {
    pub sp_namp: *mut libc::c_char,
    pub sp_pwdp: *mut libc::c_char,
    pub sp_lstchg: libc::c_long,
    pub sp_min: libc::c_long,
    pub sp_max: libc::c_long,
    pub sp_warn: libc::c_long,
    pub sp_inact: libc::c_long,
    pub sp_expire: libc::c_long,
    pub sp_flag: libc::c_ulong,
}
unsafe extern "C" fn pick_salt() -> *const libc::c_char {
    let mut pw: *mut passwd = 0 as *mut passwd;
    let mut passwd: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut p: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut typelen: size_t = 0;
    static mut salt: [libc::c_char; 32] = [0; 32];
    if salt[0 as libc::c_int as usize] as libc::c_int != '\0' as i32 {
        return salt.as_mut_ptr();
    }
    strlcpy(
        salt.as_mut_ptr(),
        b"xx\0" as *const u8 as *const libc::c_char,
        ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong,
    );
    setpwent();
    loop {
        pw = getpwent();
        if pw.is_null() {
            break;
        }
        passwd = shadow_pw(pw);
        if passwd.is_null() {
            continue;
        }
        if !(*passwd.offset(0 as libc::c_int as isize) as libc::c_int == '$' as i32 && {
            p = strrchr(passwd.offset(1 as libc::c_int as isize), '$' as i32);
            !p.is_null()
        }) {
            continue;
        }
        typelen =
            (p.offset_from(passwd) as libc::c_long + 1 as libc::c_int as libc::c_long) as size_t;
        strlcpy(
            salt.as_mut_ptr(),
            passwd,
            if typelen < ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong {
                typelen
            } else {
                ::core::mem::size_of::<[libc::c_char; 32]>() as libc::c_ulong
            },
        );
        explicit_bzero(passwd as *mut libc::c_void, strlen(passwd));
        break;
    }
    endpwent();
    return salt.as_mut_ptr();
}
#[no_mangle]
pub unsafe extern "C" fn xcrypt(
    mut password: *const libc::c_char,
    mut salt: *const libc::c_char,
) -> *mut libc::c_char {
    let mut crypted: *mut libc::c_char = 0 as *mut libc::c_char;
    if salt.is_null() {
        salt = pick_salt();
    }
    crypted = crypt(password, salt);
    return crypted;
}
#[no_mangle]
pub unsafe extern "C" fn shadow_pw(mut pw: *mut passwd) -> *mut libc::c_char {
    let mut pw_password: *mut libc::c_char = (*pw).pw_passwd;
    let mut spw: *mut spwd = getspnam((*pw).pw_name);
    if !spw.is_null() {
        pw_password = (*spw).sp_pwdp;
    }
    return pw_password;
}
