use ::c2rust_bitfields;
use ::libc;
extern "C" {
    fn __h_errno_location() -> *mut libc::c_int;
    fn __res_state() -> *mut __res_state;
    fn __res_init() -> libc::c_int;
    fn res_query(
        _: *const libc::c_char,
        _: libc::c_int,
        _: libc::c_int,
        _: *mut libc::c_uchar,
        _: libc::c_int,
    ) -> libc::c_int;
    fn dn_expand(
        _: *const libc::c_uchar,
        _: *const libc::c_uchar,
        _: *const libc::c_uchar,
        _: *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_int;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn strdup(_: *const libc::c_char) -> *mut libc::c_char;
}
pub type __u_char = libc::c_uchar;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type u_char = __u_char;
pub type u_int16_t = __uint16_t;
pub type u_int32_t = __uint32_t;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in6 {
    pub sin6_family: sa_family_t,
    pub sin6_port: in_port_t,
    pub sin6_flowinfo: uint32_t,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: uint32_t,
}
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in6_addr {
    pub __in6_u: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub __u6_addr8: [uint8_t; 16],
    pub __u6_addr16: [uint16_t; 8],
    pub __u6_addr32: [uint32_t; 4],
}
pub type uint16_t = __uint16_t;
pub type uint8_t = __uint8_t;
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_addr_t = uint32_t;
pub type __ns_type = libc::c_uint;
pub const ns_t_max: __ns_type = 65536;
pub const ns_t_dlv: __ns_type = 32769;
pub const ns_t_ta: __ns_type = 32768;
pub const ns_t_avc: __ns_type = 258;
pub const ns_t_caa: __ns_type = 257;
pub const ns_t_uri: __ns_type = 256;
pub const ns_t_any: __ns_type = 255;
pub const ns_t_maila: __ns_type = 254;
pub const ns_t_mailb: __ns_type = 253;
pub const ns_t_axfr: __ns_type = 252;
pub const ns_t_ixfr: __ns_type = 251;
pub const ns_t_tsig: __ns_type = 250;
pub const ns_t_tkey: __ns_type = 249;
pub const ns_t_eui64: __ns_type = 109;
pub const ns_t_eui48: __ns_type = 108;
pub const ns_t_lp: __ns_type = 107;
pub const ns_t_l64: __ns_type = 106;
pub const ns_t_l32: __ns_type = 105;
pub const ns_t_nid: __ns_type = 104;
pub const ns_t_unspec: __ns_type = 103;
pub const ns_t_gid: __ns_type = 102;
pub const ns_t_uid: __ns_type = 101;
pub const ns_t_uinfo: __ns_type = 100;
pub const ns_t_spf: __ns_type = 99;
pub const ns_t_csync: __ns_type = 62;
pub const ns_t_openpgpkey: __ns_type = 61;
pub const ns_t_cdnskey: __ns_type = 60;
pub const ns_t_cds: __ns_type = 59;
pub const ns_t_talink: __ns_type = 58;
pub const ns_t_rkey: __ns_type = 57;
pub const ns_t_ninfo: __ns_type = 56;
pub const ns_t_hip: __ns_type = 55;
pub const ns_t_smimea: __ns_type = 53;
pub const ns_t_tlsa: __ns_type = 52;
pub const ns_t_nsec3param: __ns_type = 51;
pub const ns_t_nsec3: __ns_type = 50;
pub const ns_t_dhcid: __ns_type = 49;
pub const ns_t_dnskey: __ns_type = 48;
pub const ns_t_nsec: __ns_type = 47;
pub const ns_t_rrsig: __ns_type = 46;
pub const ns_t_ipseckey: __ns_type = 45;
pub const ns_t_sshfp: __ns_type = 44;
pub const ns_t_ds: __ns_type = 43;
pub const ns_t_apl: __ns_type = 42;
pub const ns_t_opt: __ns_type = 41;
pub const ns_t_sink: __ns_type = 40;
pub const ns_t_dname: __ns_type = 39;
pub const ns_t_a6: __ns_type = 38;
pub const ns_t_cert: __ns_type = 37;
pub const ns_t_kx: __ns_type = 36;
pub const ns_t_naptr: __ns_type = 35;
pub const ns_t_atma: __ns_type = 34;
pub const ns_t_srv: __ns_type = 33;
pub const ns_t_nimloc: __ns_type = 32;
pub const ns_t_eid: __ns_type = 31;
pub const ns_t_nxt: __ns_type = 30;
pub const ns_t_loc: __ns_type = 29;
pub const ns_t_aaaa: __ns_type = 28;
pub const ns_t_gpos: __ns_type = 27;
pub const ns_t_px: __ns_type = 26;
pub const ns_t_key: __ns_type = 25;
pub const ns_t_sig: __ns_type = 24;
pub const ns_t_nsap_ptr: __ns_type = 23;
pub const ns_t_nsap: __ns_type = 22;
pub const ns_t_rt: __ns_type = 21;
pub const ns_t_isdn: __ns_type = 20;
pub const ns_t_x25: __ns_type = 19;
pub const ns_t_afsdb: __ns_type = 18;
pub const ns_t_rp: __ns_type = 17;
pub const ns_t_txt: __ns_type = 16;
pub const ns_t_mx: __ns_type = 15;
pub const ns_t_minfo: __ns_type = 14;
pub const ns_t_hinfo: __ns_type = 13;
pub const ns_t_ptr: __ns_type = 12;
pub const ns_t_wks: __ns_type = 11;
pub const ns_t_null: __ns_type = 10;
pub const ns_t_mr: __ns_type = 9;
pub const ns_t_mg: __ns_type = 8;
pub const ns_t_mb: __ns_type = 7;
pub const ns_t_soa: __ns_type = 6;
pub const ns_t_cname: __ns_type = 5;
pub const ns_t_mf: __ns_type = 4;
pub const ns_t_md: __ns_type = 3;
pub const ns_t_ns: __ns_type = 2;
pub const ns_t_a: __ns_type = 1;
pub const ns_t_invalid: __ns_type = 0;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct HEADER {
    #[bitfield(name = "id", ty = "libc::c_uint", bits = "0..=15")]
    #[bitfield(name = "rd", ty = "libc::c_uint", bits = "16..=16")]
    #[bitfield(name = "tc", ty = "libc::c_uint", bits = "17..=17")]
    #[bitfield(name = "aa", ty = "libc::c_uint", bits = "18..=18")]
    #[bitfield(name = "opcode", ty = "libc::c_uint", bits = "19..=22")]
    #[bitfield(name = "qr", ty = "libc::c_uint", bits = "23..=23")]
    #[bitfield(name = "rcode", ty = "libc::c_uint", bits = "24..=27")]
    #[bitfield(name = "cd", ty = "libc::c_uint", bits = "28..=28")]
    #[bitfield(name = "ad", ty = "libc::c_uint", bits = "29..=29")]
    #[bitfield(name = "unused", ty = "libc::c_uint", bits = "30..=30")]
    #[bitfield(name = "ra", ty = "libc::c_uint", bits = "31..=31")]
    #[bitfield(name = "qdcount", ty = "libc::c_uint", bits = "32..=47")]
    #[bitfield(name = "ancount", ty = "libc::c_uint", bits = "48..=63")]
    #[bitfield(name = "nscount", ty = "libc::c_uint", bits = "64..=79")]
    #[bitfield(name = "arcount", ty = "libc::c_uint", bits = "80..=95")]
    pub id_rd_tc_aa_opcode_qr_rcode_cd_ad_unused_ra_qdcount_ancount_nscount_arcount: [u8; 12],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct __res_state {
    pub retrans: libc::c_int,
    pub retry: libc::c_int,
    pub options: libc::c_ulong,
    pub nscount: libc::c_int,
    pub nsaddr_list: [sockaddr_in; 3],
    pub id: libc::c_ushort,
    pub dnsrch: [*mut libc::c_char; 7],
    pub defdname: [libc::c_char; 256],
    pub pfcode: libc::c_ulong,
    #[bitfield(name = "ndots", ty = "libc::c_uint", bits = "0..=3")]
    #[bitfield(name = "nsort", ty = "libc::c_uint", bits = "4..=7")]
    #[bitfield(name = "ipv6_unavail", ty = "libc::c_uint", bits = "8..=8")]
    #[bitfield(name = "unused", ty = "libc::c_uint", bits = "9..=31")]
    pub ndots_nsort_ipv6_unavail_unused: [u8; 4],
    pub sort_list: [C2RustUnnamed_2; 10],
    pub __glibc_unused_qhook: *mut libc::c_void,
    pub __glibc_unused_rhook: *mut libc::c_void,
    pub res_h_errno: libc::c_int,
    pub _vcsock: libc::c_int,
    pub _flags: libc::c_uint,
    pub _u: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_0 {
    pub pad: [libc::c_char; 52],
    pub _ext: C2RustUnnamed_1,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub nscount: uint16_t,
    pub nsmap: [uint16_t; 3],
    pub nssocks: [libc::c_int; 3],
    pub nscount6: uint16_t,
    pub nsinit: uint16_t,
    pub nsaddrs: [*mut sockaddr_in6; 3],
    pub __glibc_reserved: [libc::c_uint; 2],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub addr: in_addr,
    pub mask: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rdatainfo {
    pub rdi_length: libc::c_uint,
    pub rdi_data: *mut libc::c_uchar,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rrsetinfo {
    pub rri_flags: libc::c_uint,
    pub rri_rdclass: libc::c_uint,
    pub rri_rdtype: libc::c_uint,
    pub rri_ttl: libc::c_uint,
    pub rri_nrdatas: libc::c_uint,
    pub rri_nsigs: libc::c_uint,
    pub rri_name: *mut libc::c_char,
    pub rri_rdatas: *mut rdatainfo,
    pub rri_sigs: *mut rdatainfo,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dns_response {
    pub header: HEADER,
    pub query: *mut dns_query,
    pub answer: *mut dns_rr,
    pub authority: *mut dns_rr,
    pub additional: *mut dns_rr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dns_rr {
    pub name: *mut libc::c_char,
    pub type_0: u_int16_t,
    pub class: u_int16_t,
    pub ttl: u_int16_t,
    pub size: u_int16_t,
    pub rdata: *mut libc::c_void,
    pub next: *mut dns_rr,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct dns_query {
    pub name: *mut libc::c_char,
    pub type_0: u_int16_t,
    pub class: u_int16_t,
    pub next: *mut dns_query,
}
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
        | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
        as __uint16_t;
}
unsafe extern "C" fn _ssh_compat_getshort(mut msgp: *const u_char) -> u_int16_t {
    let mut u: u_int16_t = 0;
    let mut t_cp: *const libc::c_uchar = msgp as *const libc::c_uchar;
    u = ((*t_cp.offset(0 as libc::c_int as isize) as uint16_t as libc::c_int) << 8 as libc::c_int
        | *t_cp.offset(1 as libc::c_int as isize) as uint16_t as libc::c_int) as u_int16_t;
    msgp = msgp.offset(2 as libc::c_int as isize);
    return u;
}
unsafe extern "C" fn _ssh_compat_getlong(mut msgp: *const u_char) -> u_int32_t {
    let mut u: u_int32_t = 0;
    let mut t_cp: *const libc::c_uchar = msgp as *const libc::c_uchar;
    u = (*t_cp.offset(0 as libc::c_int as isize) as uint32_t) << 24 as libc::c_int
        | (*t_cp.offset(1 as libc::c_int as isize) as uint32_t) << 16 as libc::c_int
        | (*t_cp.offset(2 as libc::c_int as isize) as uint32_t) << 8 as libc::c_int
        | *t_cp.offset(3 as libc::c_int as isize) as uint32_t;
    msgp = msgp.offset(4 as libc::c_int as isize);
    return u;
}
#[no_mangle]
pub unsafe extern "C" fn getrrsetbyname(
    mut hostname: *const libc::c_char,
    mut rdclass: libc::c_uint,
    mut rdtype: libc::c_uint,
    mut flags: libc::c_uint,
    mut res: *mut *mut rrsetinfo,
) -> libc::c_int {
    let mut current_block: u64;
    let mut _resp: *mut __res_state = __res_state();
    let mut result: libc::c_int = 0;
    let mut rrset: *mut rrsetinfo = 0 as *mut rrsetinfo;
    let mut response: *mut dns_response = 0 as *mut dns_response;
    let mut rr: *mut dns_rr = 0 as *mut dns_rr;
    let mut rdata: *mut rdatainfo = 0 as *mut rdatainfo;
    let mut length: libc::c_int = 0;
    let mut index_ans: libc::c_uint = 0;
    let mut index_sig: libc::c_uint = 0;
    let mut answer: [u_char; 65535] = [0; 65535];
    if rdclass > 0xffff as libc::c_int as libc::c_uint
        || rdtype > 0xffff as libc::c_int as libc::c_uint
    {
        result = 3 as libc::c_int;
    } else if rdclass == 0xff as libc::c_int as libc::c_uint
        || rdtype == 0xff as libc::c_int as libc::c_uint
    {
        result = 3 as libc::c_int;
    } else if flags != 0 {
        result = 3 as libc::c_int;
    } else if (*_resp).options & 0x1 as libc::c_int as libc::c_ulong
        == 0 as libc::c_int as libc::c_ulong
        && __res_init() == -(1 as libc::c_int)
    {
        result = 2 as libc::c_int;
    } else {
        if (*_resp).options & 0x100000 as libc::c_int as libc::c_ulong != 0 {
            (*_resp).options |= 0x800000 as libc::c_int as libc::c_ulong;
        }
        length = res_query(
            hostname,
            rdclass as libc::c_int,
            rdtype as libc::c_int,
            answer.as_mut_ptr(),
            ::core::mem::size_of::<[u_char; 65535]>() as libc::c_ulong as libc::c_int,
        );
        if length < 0 as libc::c_int {
            match *__h_errno_location() {
                1 => {
                    result = 4 as libc::c_int;
                }
                4 => {
                    result = 5 as libc::c_int;
                }
                _ => {
                    result = 2 as libc::c_int;
                }
            }
        } else {
            response = parse_dns_response(answer.as_mut_ptr(), length);
            if response.is_null() {
                result = 2 as libc::c_int;
            } else if ((*response).header).qdcount() as libc::c_int != 1 as libc::c_int {
                result = 2 as libc::c_int;
            } else {
                rrset = calloc(
                    1 as libc::c_int as libc::c_ulong,
                    ::core::mem::size_of::<rrsetinfo>() as libc::c_ulong,
                ) as *mut rrsetinfo;
                if rrset.is_null() {
                    result = 1 as libc::c_int;
                } else {
                    (*rrset).rri_rdclass = (*(*response).query).class as libc::c_uint;
                    (*rrset).rri_rdtype = (*(*response).query).type_0 as libc::c_uint;
                    (*rrset).rri_ttl = (*(*response).answer).ttl as libc::c_uint;
                    (*rrset).rri_nrdatas = ((*response).header).ancount();
                    if ((*response).header).ad() as libc::c_int == 1 as libc::c_int {
                        (*rrset).rri_flags |= 1 as libc::c_int as libc::c_uint;
                    }
                    (*rrset).rri_name = strdup((*(*response).answer).name);
                    if ((*rrset).rri_name).is_null() {
                        result = 1 as libc::c_int;
                    } else {
                        (*rrset).rri_nrdatas = count_dns_rr(
                            (*response).answer,
                            (*rrset).rri_rdclass as u_int16_t,
                            (*rrset).rri_rdtype as u_int16_t,
                        ) as libc::c_uint;
                        (*rrset).rri_nsigs = count_dns_rr(
                            (*response).answer,
                            (*rrset).rri_rdclass as u_int16_t,
                            ns_t_rrsig as libc::c_int as u_int16_t,
                        ) as libc::c_uint;
                        (*rrset).rri_rdatas = calloc(
                            (*rrset).rri_nrdatas as libc::c_ulong,
                            ::core::mem::size_of::<rdatainfo>() as libc::c_ulong,
                        ) as *mut rdatainfo;
                        if ((*rrset).rri_rdatas).is_null() {
                            result = 1 as libc::c_int;
                        } else {
                            if (*rrset).rri_nsigs > 0 as libc::c_int as libc::c_uint {
                                (*rrset).rri_sigs = calloc(
                                    (*rrset).rri_nsigs as libc::c_ulong,
                                    ::core::mem::size_of::<rdatainfo>() as libc::c_ulong,
                                )
                                    as *mut rdatainfo;
                                if ((*rrset).rri_sigs).is_null() {
                                    result = 1 as libc::c_int;
                                    current_block = 7617683364132193329;
                                } else {
                                    current_block = 4567019141635105728;
                                }
                            } else {
                                current_block = 4567019141635105728;
                            }
                            match current_block {
                                7617683364132193329 => {}
                                _ => {
                                    rr = (*response).answer;
                                    index_ans = 0 as libc::c_int as libc::c_uint;
                                    index_sig = 0 as libc::c_int as libc::c_uint;
                                    loop {
                                        if rr.is_null() {
                                            current_block = 8151474771948790331;
                                            break;
                                        }
                                        rdata = 0 as *mut rdatainfo;
                                        if (*rr).class as libc::c_uint == (*rrset).rri_rdclass
                                            && (*rr).type_0 as libc::c_uint == (*rrset).rri_rdtype
                                        {
                                            let fresh0 = index_ans;
                                            index_ans = index_ans.wrapping_add(1);
                                            rdata = &mut *((*rrset).rri_rdatas)
                                                .offset(fresh0 as isize)
                                                as *mut rdatainfo;
                                        }
                                        if (*rr).class as libc::c_uint == (*rrset).rri_rdclass
                                            && (*rr).type_0 as libc::c_int
                                                == ns_t_rrsig as libc::c_int
                                        {
                                            let fresh1 = index_sig;
                                            index_sig = index_sig.wrapping_add(1);
                                            rdata = &mut *((*rrset).rri_sigs)
                                                .offset(fresh1 as isize)
                                                as *mut rdatainfo;
                                        }
                                        if !rdata.is_null() {
                                            (*rdata).rdi_length = (*rr).size as libc::c_uint;
                                            (*rdata).rdi_data = malloc((*rr).size as libc::c_ulong)
                                                as *mut libc::c_uchar;
                                            if ((*rdata).rdi_data).is_null() {
                                                result = 1 as libc::c_int;
                                                current_block = 7617683364132193329;
                                                break;
                                            } else {
                                                memcpy(
                                                    (*rdata).rdi_data as *mut libc::c_void,
                                                    (*rr).rdata,
                                                    (*rr).size as libc::c_ulong,
                                                );
                                            }
                                        }
                                        rr = (*rr).next;
                                    }
                                    match current_block {
                                        7617683364132193329 => {}
                                        _ => {
                                            free_dns_response(response);
                                            *res = rrset;
                                            return 0 as libc::c_int;
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
    if !rrset.is_null() {
        freerrset(rrset);
    }
    if !response.is_null() {
        free_dns_response(response);
    }
    return result;
}
#[no_mangle]
pub unsafe extern "C" fn freerrset(mut rrset: *mut rrsetinfo) {
    let mut i: u_int16_t = 0;
    if rrset.is_null() {
        return;
    }
    if !((*rrset).rri_rdatas).is_null() {
        i = 0 as libc::c_int as u_int16_t;
        while (i as libc::c_uint) < (*rrset).rri_nrdatas {
            if ((*((*rrset).rri_rdatas).offset(i as isize)).rdi_data).is_null() {
                break;
            }
            free((*((*rrset).rri_rdatas).offset(i as isize)).rdi_data as *mut libc::c_void);
            i = i.wrapping_add(1);
            i;
        }
        free((*rrset).rri_rdatas as *mut libc::c_void);
    }
    if !((*rrset).rri_sigs).is_null() {
        i = 0 as libc::c_int as u_int16_t;
        while (i as libc::c_uint) < (*rrset).rri_nsigs {
            if ((*((*rrset).rri_sigs).offset(i as isize)).rdi_data).is_null() {
                break;
            }
            free((*((*rrset).rri_sigs).offset(i as isize)).rdi_data as *mut libc::c_void);
            i = i.wrapping_add(1);
            i;
        }
        free((*rrset).rri_sigs as *mut libc::c_void);
    }
    if !((*rrset).rri_name).is_null() {
        free((*rrset).rri_name as *mut libc::c_void);
    }
    free(rrset as *mut libc::c_void);
}
unsafe extern "C" fn parse_dns_response(
    mut answer: *const u_char,
    mut size: libc::c_int,
) -> *mut dns_response {
    let mut resp: *mut dns_response = 0 as *mut dns_response;
    let mut cp: *const u_char = 0 as *const u_char;
    if size < 12 as libc::c_int {
        return 0 as *mut dns_response;
    }
    resp = calloc(
        1 as libc::c_int as libc::c_ulong,
        ::core::mem::size_of::<dns_response>() as libc::c_ulong,
    ) as *mut dns_response;
    if resp.is_null() {
        return 0 as *mut dns_response;
    }
    cp = answer;
    memcpy(
        &mut (*resp).header as *mut HEADER as *mut libc::c_void,
        cp as *const libc::c_void,
        12 as libc::c_int as libc::c_ulong,
    );
    cp = cp.offset(12 as libc::c_int as isize);
    ((*resp).header)
        .set_qdcount(__bswap_16(((*resp).header).qdcount() as __uint16_t) as libc::c_uint);
    ((*resp).header)
        .set_ancount(__bswap_16(((*resp).header).ancount() as __uint16_t) as libc::c_uint);
    ((*resp).header)
        .set_nscount(__bswap_16(((*resp).header).nscount() as __uint16_t) as libc::c_uint);
    ((*resp).header)
        .set_arcount(__bswap_16(((*resp).header).arcount() as __uint16_t) as libc::c_uint);
    if (((*resp).header).qdcount() as libc::c_int) < 1 as libc::c_int {
        free_dns_response(resp);
        return 0 as *mut dns_response;
    }
    (*resp).query = parse_dns_qsection(
        answer,
        size,
        &mut cp,
        ((*resp).header).qdcount() as libc::c_int,
    );
    if ((*resp).header).qdcount() as libc::c_int != 0 && ((*resp).query).is_null() {
        free_dns_response(resp);
        return 0 as *mut dns_response;
    }
    (*resp).answer = parse_dns_rrsection(
        answer,
        size,
        &mut cp,
        ((*resp).header).ancount() as libc::c_int,
    );
    if ((*resp).header).ancount() as libc::c_int != 0 && ((*resp).answer).is_null() {
        free_dns_response(resp);
        return 0 as *mut dns_response;
    }
    (*resp).authority = parse_dns_rrsection(
        answer,
        size,
        &mut cp,
        ((*resp).header).nscount() as libc::c_int,
    );
    if ((*resp).header).nscount() as libc::c_int != 0 && ((*resp).authority).is_null() {
        free_dns_response(resp);
        return 0 as *mut dns_response;
    }
    (*resp).additional = parse_dns_rrsection(
        answer,
        size,
        &mut cp,
        ((*resp).header).arcount() as libc::c_int,
    );
    if ((*resp).header).arcount() as libc::c_int != 0 && ((*resp).additional).is_null() {
        free_dns_response(resp);
        return 0 as *mut dns_response;
    }
    return resp;
}
unsafe extern "C" fn parse_dns_qsection(
    mut answer: *const u_char,
    mut size: libc::c_int,
    mut cp: *mut *const u_char,
    mut count: libc::c_int,
) -> *mut dns_query {
    let mut head: *mut dns_query = 0 as *mut dns_query;
    let mut curr: *mut dns_query = 0 as *mut dns_query;
    let mut prev: *mut dns_query = 0 as *mut dns_query;
    let mut i: libc::c_int = 0;
    let mut length: libc::c_int = 0;
    let mut name: [libc::c_char; 1025] = [0; 1025];
    i = 1 as libc::c_int;
    head = 0 as *mut dns_query;
    prev = 0 as *mut dns_query;
    while i <= count {
        if !(*cp >= answer.offset(size as isize)) {
            curr = calloc(
                1 as libc::c_int as libc::c_ulong,
                ::core::mem::size_of::<dns_query>() as libc::c_ulong,
            ) as *mut dns_query;
            if !curr.is_null() {
                if head.is_null() {
                    head = curr;
                }
                if !prev.is_null() {
                    (*prev).next = curr;
                }
                length = dn_expand(
                    answer,
                    answer.offset(size as isize),
                    *cp,
                    name.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as libc::c_int,
                );
                if length < 0 as libc::c_int {
                    free_dns_query(head);
                    return 0 as *mut dns_query;
                }
                (*curr).name = strdup(name.as_mut_ptr());
                if ((*curr).name).is_null() {
                    free_dns_query(head);
                    return 0 as *mut dns_query;
                }
                if !((*cp).offset(length as isize) > answer.offset(size as isize)) {
                    *cp = (*cp).offset(length as isize);
                    if !((*cp).offset(2 as libc::c_int as isize) > answer.offset(size as isize)) {
                        (*curr).type_0 = _ssh_compat_getshort(*cp);
                        *cp = (*cp).offset(2 as libc::c_int as isize);
                        if !((*cp).offset(2 as libc::c_int as isize) > answer.offset(size as isize))
                        {
                            (*curr).class = _ssh_compat_getshort(*cp);
                            *cp = (*cp).offset(2 as libc::c_int as isize);
                            i += 1;
                            i;
                            prev = curr;
                            continue;
                        }
                    }
                }
            }
        }
        free_dns_query(head);
        return 0 as *mut dns_query;
    }
    return head;
}
unsafe extern "C" fn parse_dns_rrsection(
    mut answer: *const u_char,
    mut size: libc::c_int,
    mut cp: *mut *const u_char,
    mut count: libc::c_int,
) -> *mut dns_rr {
    let mut head: *mut dns_rr = 0 as *mut dns_rr;
    let mut curr: *mut dns_rr = 0 as *mut dns_rr;
    let mut prev: *mut dns_rr = 0 as *mut dns_rr;
    let mut i: libc::c_int = 0;
    let mut length: libc::c_int = 0;
    let mut name: [libc::c_char; 1025] = [0; 1025];
    i = 1 as libc::c_int;
    head = 0 as *mut dns_rr;
    prev = 0 as *mut dns_rr;
    while i <= count {
        if !(*cp >= answer.offset(size as isize)) {
            curr = calloc(
                1 as libc::c_int as libc::c_ulong,
                ::core::mem::size_of::<dns_rr>() as libc::c_ulong,
            ) as *mut dns_rr;
            if !curr.is_null() {
                if head.is_null() {
                    head = curr;
                }
                if !prev.is_null() {
                    (*prev).next = curr;
                }
                length = dn_expand(
                    answer,
                    answer.offset(size as isize),
                    *cp,
                    name.as_mut_ptr(),
                    ::core::mem::size_of::<[libc::c_char; 1025]>() as libc::c_ulong as libc::c_int,
                );
                if length < 0 as libc::c_int {
                    free_dns_rr(head);
                    return 0 as *mut dns_rr;
                }
                (*curr).name = strdup(name.as_mut_ptr());
                if ((*curr).name).is_null() {
                    free_dns_rr(head);
                    return 0 as *mut dns_rr;
                }
                if !((*cp).offset(length as isize) > answer.offset(size as isize)) {
                    *cp = (*cp).offset(length as isize);
                    if !((*cp).offset(2 as libc::c_int as isize) > answer.offset(size as isize)) {
                        (*curr).type_0 = _ssh_compat_getshort(*cp);
                        *cp = (*cp).offset(2 as libc::c_int as isize);
                        if !((*cp).offset(2 as libc::c_int as isize) > answer.offset(size as isize))
                        {
                            (*curr).class = _ssh_compat_getshort(*cp);
                            *cp = (*cp).offset(2 as libc::c_int as isize);
                            if !((*cp).offset(4 as libc::c_int as isize)
                                > answer.offset(size as isize))
                            {
                                (*curr).ttl = _ssh_compat_getlong(*cp) as u_int16_t;
                                *cp = (*cp).offset(4 as libc::c_int as isize);
                                if !((*cp).offset(2 as libc::c_int as isize)
                                    > answer.offset(size as isize))
                                {
                                    (*curr).size = _ssh_compat_getshort(*cp);
                                    *cp = (*cp).offset(2 as libc::c_int as isize);
                                    if !((*cp).offset((*curr).size as libc::c_int as isize)
                                        > answer.offset(size as isize))
                                    {
                                        (*curr).rdata = malloc((*curr).size as libc::c_ulong);
                                        if ((*curr).rdata).is_null() {
                                            free_dns_rr(head);
                                            return 0 as *mut dns_rr;
                                        }
                                        memcpy(
                                            (*curr).rdata,
                                            *cp as *const libc::c_void,
                                            (*curr).size as libc::c_ulong,
                                        );
                                        *cp = (*cp).offset((*curr).size as libc::c_int as isize);
                                        i += 1;
                                        i;
                                        prev = curr;
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        free_dns_rr(head);
        return 0 as *mut dns_rr;
    }
    return head;
}
unsafe extern "C" fn free_dns_query(mut p: *mut dns_query) {
    if p.is_null() {
        return;
    }
    if !((*p).name).is_null() {
        free((*p).name as *mut libc::c_void);
    }
    free_dns_query((*p).next);
    free(p as *mut libc::c_void);
}
unsafe extern "C" fn free_dns_rr(mut p: *mut dns_rr) {
    if p.is_null() {
        return;
    }
    if !((*p).name).is_null() {
        free((*p).name as *mut libc::c_void);
    }
    if !((*p).rdata).is_null() {
        free((*p).rdata);
    }
    free_dns_rr((*p).next);
    free(p as *mut libc::c_void);
}
unsafe extern "C" fn free_dns_response(mut p: *mut dns_response) {
    if p.is_null() {
        return;
    }
    free_dns_query((*p).query);
    free_dns_rr((*p).answer);
    free_dns_rr((*p).authority);
    free_dns_rr((*p).additional);
    free(p as *mut libc::c_void);
}
unsafe extern "C" fn count_dns_rr(
    mut p: *mut dns_rr,
    mut class: u_int16_t,
    mut type_0: u_int16_t,
) -> libc::c_int {
    let mut n: libc::c_int = 0 as libc::c_int;
    while !p.is_null() {
        if (*p).class as libc::c_int == class as libc::c_int
            && (*p).type_0 as libc::c_int == type_0 as libc::c_int
        {
            n += 1;
            n;
        }
        p = (*p).next;
    }
    return n;
}
