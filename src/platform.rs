use ::libc;
extern "C" {
    fn oom_adjust_setup();
    fn oom_adjust_restore();
    fn geteuid() -> __uid_t;
    
    fn strncmp(_: *const libc::c_char, _: *const libc::c_char, _: libc::c_ulong) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn auth_shadow_acctexpired(_: *mut spwd) -> libc::c_int;
    fn getspnam(__name: *const libc::c_char) -> *mut spwd;
}
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __pid_t = libc::c_int;
pub type pid_t = __pid_t;

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
pub unsafe extern "C" fn platform_pre_listen() {
    oom_adjust_setup();
}
pub unsafe extern "C" fn platform_pre_fork() {}
pub unsafe extern "C" fn platform_pre_restart() {
    oom_adjust_restore();
}
pub unsafe extern "C" fn platform_post_fork_parent(mut _child_pid: pid_t) {}
pub unsafe extern "C" fn platform_post_fork_child() {
    oom_adjust_restore();
}
pub unsafe extern "C" fn platform_privileged_uidswap() -> libc::c_int {
    return (libc::getuid() == 0 as libc::c_int as libc::c_uint
        || geteuid() == 0 as libc::c_int as libc::c_uint) as libc::c_int;
}
pub unsafe extern "C" fn platform_setusercontext(mut _pw: *mut libc::passwd) {}
pub unsafe extern "C" fn platform_setusercontext_post_groups(mut _pw: *mut libc::passwd) {}
pub unsafe extern "C" fn platform_krb5_get_principal_name(
    mut _pw_name: *const libc::c_char,
) -> *mut libc::c_char {
    return 0 as *mut libc::c_char;
}
pub unsafe extern "C" fn platform_locked_account(mut pw: *mut libc::passwd) -> libc::c_int {
    let mut locked: libc::c_int = 0 as libc::c_int;
    let mut passwd: *mut libc::c_char = (*pw).pw_passwd;
    let mut spw: *mut spwd = 0 as *mut spwd;
    spw = getspnam((*pw).pw_name);
    if !spw.is_null() && auth_shadow_acctexpired(spw) != 0 {
        return 1 as libc::c_int;
    }
    if !spw.is_null() {
        passwd = (*spw).sp_pwdp;
    }
    if !passwd.is_null() && *passwd as libc::c_int != 0 {
        if strncmp(
            passwd,
            b"!\0" as *const u8 as *const libc::c_char,
            strlen(b"!\0" as *const u8 as *const libc::c_char),
        ) == 0 as libc::c_int
        {
            locked = 1 as libc::c_int;
        }
    }
    return locked;
}
