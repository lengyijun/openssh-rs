use ::libc;
extern "C" {
    fn getsockopt(
        __fd: libc::c_int,
        __level: libc::c_int,
        __optname: libc::c_int,
        __optval: *mut libc::c_void,
        __optlen: *mut socklen_t,
    ) -> libc::c_int;
}
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __pid_t = libc::c_int;
pub type __socklen_t = libc::c_uint;
pub type gid_t = __gid_t;
pub type uid_t = __uid_t;
pub type pid_t = __pid_t;
pub type socklen_t = __socklen_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ucred {
    pub pid: pid_t,
    pub uid: uid_t,
    pub gid: gid_t,
}
#[no_mangle]
pub unsafe extern "C" fn getpeereid(
    mut s: libc::c_int,
    mut euid: *mut uid_t,
    mut gid: *mut gid_t,
) -> libc::c_int {
    let mut cred: ucred = ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len: socklen_t = ::core::mem::size_of::<ucred>() as libc::c_ulong as socklen_t;
    if getsockopt(
        s,
        1 as libc::c_int,
        17 as libc::c_int,
        &mut cred as *mut ucred as *mut libc::c_void,
        &mut len,
    ) < 0 as libc::c_int
    {
        return -(1 as libc::c_int);
    }
    *euid = cred.uid;
    *gid = cred.gid;
    return 0 as libc::c_int;
}
