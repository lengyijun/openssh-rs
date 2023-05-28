use crate::sftp_client::sftp_conn;
use crate::sftp_common::Attrib;
use ::libc;

extern "C" {

    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
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

    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn xrecallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;
    fn xstrdup(_: *const libc::c_char) -> *mut libc::c_char;
    fn can_get_users_groups_by_id(conn: *mut sftp_conn) -> libc::c_int;
    fn do_get_users_groups_by_id(
        conn: *mut sftp_conn,
        uids: *const u_int,
        nuids: u_int,
        gids: *const u_int,
        ngids: u_int,
        usernamesp: *mut *mut *mut libc::c_char,
        groupnamesp: *mut *mut *mut libc::c_char,
    ) -> libc::c_int;
}
pub type __u_int = libc::c_uint;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __dev_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __gid_t = libc::c_uint;
pub type __ino_t = libc::c_ulong;
pub type __mode_t = libc::c_uint;
pub type __nlink_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __time_t = libc::c_long;
pub type __blksize_t = libc::c_long;
pub type __blkcnt_t = libc::c_long;
pub type __syscall_slong_t = libc::c_long;
pub type u_int = __u_int;
pub type gid_t = __gid_t;
pub type uid_t = __uid_t;
pub type size_t = libc::c_ulong;
pub type u_int32_t = __uint32_t;
pub type u_int64_t = __uint64_t;

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
pub struct SFTP_DIRENT {
    pub filename: *mut libc::c_char,
    pub longname: *mut libc::c_char,
    pub a: Attrib,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct idname_tree {
    pub rbh_root: *mut idname,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct idname {
    pub id: u_int,
    pub name: *mut libc::c_char,
    pub entry: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub rbe_left: *mut idname,
    pub rbe_right: *mut idname,
    pub rbe_parent: *mut idname,
    pub rbe_color: libc::c_int,
}
unsafe extern "C" fn idname_cmp(mut a: *mut idname, mut b: *mut idname) -> libc::c_int {
    if (*a).id == (*b).id {
        return 0 as libc::c_int;
    }
    return if (*a).id > (*b).id {
        1 as libc::c_int
    } else {
        -(1 as libc::c_int)
    };
}
unsafe extern "C" fn idname_tree_RB_INSERT(
    mut head: *mut idname_tree,
    mut elm: *mut idname,
) -> *mut idname {
    let mut tmp: *mut idname = 0 as *mut idname;
    let mut parent: *mut idname = 0 as *mut idname;
    let mut comp: libc::c_int = 0 as libc::c_int;
    tmp = (*head).rbh_root;
    while !tmp.is_null() {
        parent = tmp;
        comp = idname_cmp(elm, parent);
        if comp < 0 as libc::c_int {
            tmp = (*tmp).entry.rbe_left;
        } else if comp > 0 as libc::c_int {
            tmp = (*tmp).entry.rbe_right;
        } else {
            return tmp;
        }
    }
    (*elm).entry.rbe_parent = parent;
    (*elm).entry.rbe_right = 0 as *mut idname;
    (*elm).entry.rbe_left = (*elm).entry.rbe_right;
    (*elm).entry.rbe_color = 1 as libc::c_int;
    if !parent.is_null() {
        if comp < 0 as libc::c_int {
            (*parent).entry.rbe_left = elm;
        } else {
            (*parent).entry.rbe_right = elm;
        }
    } else {
        (*head).rbh_root = elm;
    }
    idname_tree_RB_INSERT_COLOR(head, elm);
    return 0 as *mut idname;
}
unsafe extern "C" fn idname_tree_RB_INSERT_COLOR(mut head: *mut idname_tree, mut elm: *mut idname) {
    let mut parent: *mut idname = 0 as *mut idname;
    let mut gparent: *mut idname = 0 as *mut idname;
    let mut tmp: *mut idname = 0 as *mut idname;
    loop {
        parent = (*elm).entry.rbe_parent;
        if !(!parent.is_null() && (*parent).entry.rbe_color == 1 as libc::c_int) {
            break;
        }
        gparent = (*parent).entry.rbe_parent;
        if parent == (*gparent).entry.rbe_left {
            tmp = (*gparent).entry.rbe_right;
            if !tmp.is_null() && (*tmp).entry.rbe_color == 1 as libc::c_int {
                (*tmp).entry.rbe_color = 0 as libc::c_int;
                (*parent).entry.rbe_color = 0 as libc::c_int;
                (*gparent).entry.rbe_color = 1 as libc::c_int;
                elm = gparent;
            } else {
                if (*parent).entry.rbe_right == elm {
                    tmp = (*parent).entry.rbe_right;
                    (*parent).entry.rbe_right = (*tmp).entry.rbe_left;
                    if !((*parent).entry.rbe_right).is_null() {
                        (*(*tmp).entry.rbe_left).entry.rbe_parent = parent;
                    }
                    (*tmp).entry.rbe_parent = (*parent).entry.rbe_parent;
                    if !((*tmp).entry.rbe_parent).is_null() {
                        if parent == (*(*parent).entry.rbe_parent).entry.rbe_left {
                            (*(*parent).entry.rbe_parent).entry.rbe_left = tmp;
                        } else {
                            (*(*parent).entry.rbe_parent).entry.rbe_right = tmp;
                        }
                    } else {
                        (*head).rbh_root = tmp;
                    }
                    (*tmp).entry.rbe_left = parent;
                    (*parent).entry.rbe_parent = tmp;
                    !((*tmp).entry.rbe_parent).is_null();
                    tmp = parent;
                    parent = elm;
                    elm = tmp;
                }
                (*parent).entry.rbe_color = 0 as libc::c_int;
                (*gparent).entry.rbe_color = 1 as libc::c_int;
                tmp = (*gparent).entry.rbe_left;
                (*gparent).entry.rbe_left = (*tmp).entry.rbe_right;
                if !((*gparent).entry.rbe_left).is_null() {
                    (*(*tmp).entry.rbe_right).entry.rbe_parent = gparent;
                }
                (*tmp).entry.rbe_parent = (*gparent).entry.rbe_parent;
                if !((*tmp).entry.rbe_parent).is_null() {
                    if gparent == (*(*gparent).entry.rbe_parent).entry.rbe_left {
                        (*(*gparent).entry.rbe_parent).entry.rbe_left = tmp;
                    } else {
                        (*(*gparent).entry.rbe_parent).entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).entry.rbe_right = gparent;
                (*gparent).entry.rbe_parent = tmp;
                !((*tmp).entry.rbe_parent).is_null();
            }
        } else {
            tmp = (*gparent).entry.rbe_left;
            if !tmp.is_null() && (*tmp).entry.rbe_color == 1 as libc::c_int {
                (*tmp).entry.rbe_color = 0 as libc::c_int;
                (*parent).entry.rbe_color = 0 as libc::c_int;
                (*gparent).entry.rbe_color = 1 as libc::c_int;
                elm = gparent;
            } else {
                if (*parent).entry.rbe_left == elm {
                    tmp = (*parent).entry.rbe_left;
                    (*parent).entry.rbe_left = (*tmp).entry.rbe_right;
                    if !((*parent).entry.rbe_left).is_null() {
                        (*(*tmp).entry.rbe_right).entry.rbe_parent = parent;
                    }
                    (*tmp).entry.rbe_parent = (*parent).entry.rbe_parent;
                    if !((*tmp).entry.rbe_parent).is_null() {
                        if parent == (*(*parent).entry.rbe_parent).entry.rbe_left {
                            (*(*parent).entry.rbe_parent).entry.rbe_left = tmp;
                        } else {
                            (*(*parent).entry.rbe_parent).entry.rbe_right = tmp;
                        }
                    } else {
                        (*head).rbh_root = tmp;
                    }
                    (*tmp).entry.rbe_right = parent;
                    (*parent).entry.rbe_parent = tmp;
                    !((*tmp).entry.rbe_parent).is_null();
                    tmp = parent;
                    parent = elm;
                    elm = tmp;
                }
                (*parent).entry.rbe_color = 0 as libc::c_int;
                (*gparent).entry.rbe_color = 1 as libc::c_int;
                tmp = (*gparent).entry.rbe_right;
                (*gparent).entry.rbe_right = (*tmp).entry.rbe_left;
                if !((*gparent).entry.rbe_right).is_null() {
                    (*(*tmp).entry.rbe_left).entry.rbe_parent = gparent;
                }
                (*tmp).entry.rbe_parent = (*gparent).entry.rbe_parent;
                if !((*tmp).entry.rbe_parent).is_null() {
                    if gparent == (*(*gparent).entry.rbe_parent).entry.rbe_left {
                        (*(*gparent).entry.rbe_parent).entry.rbe_left = tmp;
                    } else {
                        (*(*gparent).entry.rbe_parent).entry.rbe_right = tmp;
                    }
                } else {
                    (*head).rbh_root = tmp;
                }
                (*tmp).entry.rbe_left = gparent;
                (*gparent).entry.rbe_parent = tmp;
                !((*tmp).entry.rbe_parent).is_null();
            }
        }
    }
    (*(*head).rbh_root).entry.rbe_color = 0 as libc::c_int;
}
unsafe extern "C" fn idname_tree_RB_FIND(
    mut head: *mut idname_tree,
    mut elm: *mut idname,
) -> *mut idname {
    let mut tmp: *mut idname = (*head).rbh_root;
    let mut comp: libc::c_int = 0;
    while !tmp.is_null() {
        comp = idname_cmp(elm, tmp);
        if comp < 0 as libc::c_int {
            tmp = (*tmp).entry.rbe_left;
        } else if comp > 0 as libc::c_int {
            tmp = (*tmp).entry.rbe_right;
        } else {
            return tmp;
        }
    }
    return 0 as *mut idname;
}
static mut user_idname: idname_tree = {
    let mut init = idname_tree {
        rbh_root: 0 as *const idname as *mut idname,
    };
    init
};
static mut group_idname: idname_tree = {
    let mut init = idname_tree {
        rbh_root: 0 as *const idname as *mut idname,
    };
    init
};
unsafe extern "C" fn idname_free(mut idname: *mut idname) {
    if idname.is_null() {
        return;
    }
    libc::free((*idname).name as *mut libc::c_void);
    libc::free(idname as *mut libc::c_void);
}
unsafe extern "C" fn idname_enter(
    mut tree: *mut idname_tree,
    mut id: u_int,
    mut name: *const libc::c_char,
) {
    let mut idname: *mut idname = 0 as *mut idname;
    idname = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<idname>() as libc::c_ulong,
    ) as *mut idname;
    if idname.is_null() {
        sshfatal(
            b"sftp-usergroup.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"idname_enter\0")).as_ptr(),
            70 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_FATAL,
            0 as *const libc::c_char,
            b"alloc\0" as *const u8 as *const libc::c_char,
        );
    }
    (*idname).id = id;
    (*idname).name = xstrdup(name);
    if !(idname_tree_RB_INSERT(tree, idname)).is_null() {
        idname_free(idname);
    }
}
unsafe extern "C" fn idname_lookup(
    mut tree: *mut idname_tree,
    mut id: u_int,
) -> *const libc::c_char {
    let mut idname: idname = idname {
        id: 0,
        name: 0 as *mut libc::c_char,
        entry: C2RustUnnamed {
            rbe_left: 0 as *mut idname,
            rbe_right: 0 as *mut idname,
            rbe_parent: 0 as *mut idname,
            rbe_color: 0,
        },
    };
    let mut found: *mut idname = 0 as *mut idname;
    memset(
        &mut idname as *mut idname as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<idname>() as libc::c_ulong,
    );
    idname.id = id;
    found = idname_tree_RB_FIND(tree, &mut idname);
    if !found.is_null() {
        return (*found).name;
    }
    return 0 as *const libc::c_char;
}
unsafe extern "C" fn freenames(mut names: *mut *mut libc::c_char, mut nnames: u_int) {
    let mut i: u_int = 0;
    if names.is_null() {
        return;
    }
    i = 0 as libc::c_int as u_int;
    while i < nnames {
        libc::free(*names.offset(i as isize) as *mut libc::c_void);
        i = i.wrapping_add(1);
        i;
    }
    libc::free(names as *mut libc::c_void);
}
unsafe extern "C" fn lookup_and_record(
    mut conn: *mut sftp_conn,
    mut uids: *mut u_int,
    mut nuids: u_int,
    mut gids: *mut u_int,
    mut ngids: u_int,
) {
    let mut r: libc::c_int = 0;
    let mut i: u_int = 0;
    let mut usernames: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    let mut groupnames: *mut *mut libc::c_char = 0 as *mut *mut libc::c_char;
    r = do_get_users_groups_by_id(
        conn,
        uids,
        nuids,
        gids,
        ngids,
        &mut usernames,
        &mut groupnames,
    );
    if r != 0 as libc::c_int {
        crate::log::sshlog(
            b"sftp-usergroup.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"lookup_and_record\0"))
                .as_ptr(),
            111 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            ssh_err(r),
            b"do_get_users_groups_by_id\0" as *const u8 as *const libc::c_char,
        );
        return;
    }
    i = 0 as libc::c_int as u_int;
    while i < nuids {
        if (*usernames.offset(i as isize)).is_null() {
            crate::log::sshlog(
                b"sftp-usergroup.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"lookup_and_record\0"))
                    .as_ptr(),
                116 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"uid %u not resolved\0" as *const u8 as *const libc::c_char,
                *uids.offset(i as isize),
            );
        } else {
            crate::log::sshlog(
                b"sftp-usergroup.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"lookup_and_record\0"))
                    .as_ptr(),
                119 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"record uid %u => \"%s\"\0" as *const u8 as *const libc::c_char,
                *uids.offset(i as isize),
                *usernames.offset(i as isize),
            );
            idname_enter(
                &mut user_idname,
                *uids.offset(i as isize),
                *usernames.offset(i as isize),
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    i = 0 as libc::c_int as u_int;
    while i < ngids {
        if (*groupnames.offset(i as isize)).is_null() {
            crate::log::sshlog(
                b"sftp-usergroup.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"lookup_and_record\0"))
                    .as_ptr(),
                124 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"gid %u not resolved\0" as *const u8 as *const libc::c_char,
                *gids.offset(i as isize),
            );
        } else {
            crate::log::sshlog(
                b"sftp-usergroup.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"lookup_and_record\0"))
                    .as_ptr(),
                127 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG3,
                0 as *const libc::c_char,
                b"record gid %u => \"%s\"\0" as *const u8 as *const libc::c_char,
                *gids.offset(i as isize),
                *groupnames.offset(i as isize),
            );
            idname_enter(
                &mut group_idname,
                *gids.offset(i as isize),
                *groupnames.offset(i as isize),
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    freenames(usernames, nuids);
    freenames(groupnames, ngids);
}
unsafe extern "C" fn has_id(mut id: u_int, mut ids: *mut u_int, mut nids: u_int) -> libc::c_int {
    let mut i: u_int = 0;
    if nids == 0 as libc::c_int as libc::c_uint {
        return 0 as libc::c_int;
    }
    i = 0 as libc::c_int as u_int;
    while i < nids {
        if *ids.offset(i as isize) == id {
            break;
        }
        i = i.wrapping_add(1);
        i;
    }
    return (i < nids) as libc::c_int;
}
unsafe extern "C" fn collect_ids_from_glob(
    mut g: *mut crate::openbsd_compat::glob::_ssh_compat_glob_t,
    mut user: libc::c_int,
    mut idsp: *mut *mut u_int,
    mut nidsp: *mut u_int,
) {
    let mut id: u_int = 0;
    let mut i: u_int = 0;
    let mut n: u_int = 0 as libc::c_int as u_int;
    let mut ids: *mut u_int = 0 as *mut u_int;
    let mut current_block_4: u64;
    i = 0 as libc::c_int as u_int;
    while !(*((*g).gl_pathv).offset(i as isize)).is_null() {
        if user != 0 {
            if !(ruser_name((**((*g).gl_statv).offset(i as isize)).st_uid)).is_null() {
                current_block_4 = 11174649648027449784;
            } else {
                id = (**((*g).gl_statv).offset(i as isize)).st_uid;
                current_block_4 = 7351195479953500246;
            }
        } else if !(rgroup_name((**((*g).gl_statv).offset(i as isize)).st_gid)).is_null() {
            current_block_4 = 11174649648027449784;
        } else {
            id = (**((*g).gl_statv).offset(i as isize)).st_gid;
            current_block_4 = 7351195479953500246;
        }
        match current_block_4 {
            7351195479953500246 => {
                if !(has_id(id, ids, n) != 0) {
                    ids = xrecallocarray(
                        ids as *mut libc::c_void,
                        n as size_t,
                        n.wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
                        ::core::mem::size_of::<u_int>() as libc::c_ulong,
                    ) as *mut u_int;
                    let fresh0 = n;
                    n = n.wrapping_add(1);
                    *ids.offset(fresh0 as isize) = id;
                }
            }
            _ => {}
        }
        i = i.wrapping_add(1);
        i;
    }
    *idsp = ids;
    *nidsp = n;
}
pub unsafe extern "C" fn get_remote_user_groups_from_glob(
    mut conn: *mut sftp_conn,
    mut g: *mut crate::openbsd_compat::glob::_ssh_compat_glob_t,
) {
    let mut uids: *mut u_int = 0 as *mut u_int;
    let mut nuids: u_int = 0 as libc::c_int as u_int;
    let mut gids: *mut u_int = 0 as *mut u_int;
    let mut ngids: u_int = 0 as libc::c_int as u_int;
    if can_get_users_groups_by_id(conn) == 0 {
        return;
    }
    collect_ids_from_glob(g, 1 as libc::c_int, &mut uids, &mut nuids);
    collect_ids_from_glob(g, 0 as libc::c_int, &mut gids, &mut ngids);
    lookup_and_record(conn, uids, nuids, gids, ngids);
    libc::free(uids as *mut libc::c_void);
    libc::free(gids as *mut libc::c_void);
}
unsafe extern "C" fn collect_ids_from_dirents(
    mut d: *mut *mut SFTP_DIRENT,
    mut user: libc::c_int,
    mut idsp: *mut *mut u_int,
    mut nidsp: *mut u_int,
) {
    let mut id: u_int = 0;
    let mut i: u_int = 0;
    let mut n: u_int = 0 as libc::c_int as u_int;
    let mut ids: *mut u_int = 0 as *mut u_int;
    let mut current_block_4: u64;
    i = 0 as libc::c_int as u_int;
    while !(*d.offset(i as isize)).is_null() {
        if user != 0 {
            if !(ruser_name((**d.offset(i as isize)).a.uid)).is_null() {
                current_block_4 = 11174649648027449784;
            } else {
                id = (**d.offset(i as isize)).a.uid;
                current_block_4 = 7351195479953500246;
            }
        } else if !(rgroup_name((**d.offset(i as isize)).a.gid)).is_null() {
            current_block_4 = 11174649648027449784;
        } else {
            id = (**d.offset(i as isize)).a.gid;
            current_block_4 = 7351195479953500246;
        }
        match current_block_4 {
            7351195479953500246 => {
                if !(has_id(id, ids, n) != 0) {
                    ids = xrecallocarray(
                        ids as *mut libc::c_void,
                        n as size_t,
                        n.wrapping_add(1 as libc::c_int as libc::c_uint) as size_t,
                        ::core::mem::size_of::<u_int>() as libc::c_ulong,
                    ) as *mut u_int;
                    let fresh1 = n;
                    n = n.wrapping_add(1);
                    *ids.offset(fresh1 as isize) = id;
                }
            }
            _ => {}
        }
        i = i.wrapping_add(1);
        i;
    }
    *idsp = ids;
    *nidsp = n;
}
pub unsafe extern "C" fn get_remote_user_groups_from_dirents(
    mut conn: *mut sftp_conn,
    mut d: *mut *mut SFTP_DIRENT,
) {
    let mut uids: *mut u_int = 0 as *mut u_int;
    let mut nuids: u_int = 0 as libc::c_int as u_int;
    let mut gids: *mut u_int = 0 as *mut u_int;
    let mut ngids: u_int = 0 as libc::c_int as u_int;
    if can_get_users_groups_by_id(conn) == 0 {
        return;
    }
    collect_ids_from_dirents(d, 1 as libc::c_int, &mut uids, &mut nuids);
    collect_ids_from_dirents(d, 0 as libc::c_int, &mut gids, &mut ngids);
    lookup_and_record(conn, uids, nuids, gids, ngids);
    libc::free(uids as *mut libc::c_void);
    libc::free(gids as *mut libc::c_void);
}
pub unsafe extern "C" fn ruser_name(mut uid: uid_t) -> *const libc::c_char {
    return idname_lookup(&mut user_idname, uid);
}
pub unsafe extern "C" fn rgroup_name(mut gid: uid_t) -> *const libc::c_char {
    return idname_lookup(&mut group_idname, gid);
}
