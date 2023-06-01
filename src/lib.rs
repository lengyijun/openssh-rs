#![allow(dead_code)]
#![allow(mutable_transmutes)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unused_assignments)]
#![allow(unused_mut)]
#![feature(c_variadic)]
#![feature(extern_types)]
#![feature(const_maybe_uninit_zeroed)]

#[macro_use]
extern crate c2rust_bitfields;
extern crate libc;
pub mod addr;
pub mod addrmatch;
pub mod atomicio;
pub mod audit;
pub mod audit_bsm;
pub mod audit_linux;
pub mod auth;
pub mod auth2;
pub mod auth2_chall;
pub mod auth2_gss;
pub mod auth2_hostbased;
pub mod auth2_kbdint;
pub mod auth2_none;
pub mod auth2_passwd;
pub mod auth2_pubkey;
pub mod auth2_pubkeyfile;
pub mod auth_bsdauth;
pub mod auth_krb5;
pub mod auth_options;
pub mod auth_pam;
pub mod auth_passwd;
pub mod auth_rhosts;
pub mod auth_shadow;
pub mod auth_sia;
pub mod authfd;
pub mod authfile;
pub mod bitmap;
pub mod canohost;
pub mod chacha;
pub mod channels;
pub mod cipher;
pub mod cipher_aes;
pub mod cipher_aesctr;
pub mod cipher_chachapoly;
pub mod cipher_chachapoly_libcrypto;
pub mod cleanup;
pub mod clientloop;
pub mod compat;
pub mod dh;
pub mod digest_libc;
pub mod digest_openssl;
pub mod dispatch;
pub mod dns;
pub mod ed25519;
pub mod entropy;
pub mod fatal;
pub mod groupaccess;
pub mod gss_genr;
pub mod gss_serv;
pub mod gss_serv_krb5;
pub mod hash;
pub mod hmac;
pub mod hostfile;
pub mod kex;
pub mod kexc25519;
pub mod kexdh;
pub mod kexecdh;
pub mod kexgen;
pub mod kexgex;
pub mod kexgexc;
pub mod kexgexs;
pub mod kexsntrup761x25519;
pub mod krl;
pub mod log;
pub mod loginrec;
pub mod mac;
pub mod misc;
pub mod moduli;
pub mod monitor;
pub mod monitor_fdpass;
pub mod monitor_wrap;
pub mod msg;
pub mod mux;
pub mod nchan;
pub mod openbsd_compat {
    pub mod arc4random;
    pub mod arc4random_uniform;
    pub mod base64;
    pub mod basename;
    pub mod bcrypt_pbkdf;
    pub mod bindresvport;
    pub mod blowfish;
    pub mod bsd_asprintf;
    pub mod bsd_closefrom;
    pub mod bsd_cygwin_util;
    pub mod bsd_err;
    pub mod bsd_flock;
    pub mod bsd_getentropy;
    pub mod bsd_getline;
    pub mod bsd_getpagesize;
    pub mod bsd_getpeereid;
    pub mod bsd_malloc;
    pub mod bsd_misc;
    pub mod bsd_nextstep;
    pub mod bsd_openpty;
    pub mod bsd_poll;
    pub mod bsd_pselect;
    pub mod bsd_setres_id;
    pub mod bsd_signal;
    pub mod bsd_snprintf;
    pub mod bsd_statvfs;
    pub mod bsd_timegm;
    pub mod bsd_waitpid;
    pub mod daemon;
    pub mod dirname;
    pub mod explicit_bzero;
    pub mod fake_rfc2553;
    pub mod fmt_scaled;
    pub mod fnmatch;
    pub mod freezero;
    pub mod getcwd;
    pub mod getgrouplist;
    pub mod getopt_long;
    pub mod getrrsetbyname;
    pub mod getrrsetbyname_ldns;
    pub mod glob;
    pub mod inet_aton;
    pub mod inet_ntoa;
    pub mod inet_ntop;
    pub mod kludge_fd_set;
    pub mod libressl_api_compat;
    pub mod md5;
    pub mod memmem;
    pub mod mktemp;
    pub mod openssl_compat;
    pub mod port_aix;
    pub mod port_irix;
    pub mod port_linux;
    pub mod port_net;
    pub mod port_prngd;
    pub mod port_solaris;
    pub mod port_uw;
    pub mod pwcache;
    pub mod readpassphrase;
    pub mod reallocarray;
    pub mod recallocarray;
    pub mod rresvport;
    pub mod setenv;
    pub mod setproctitle;
    pub mod sha1;
    pub mod sha2;
    pub mod sigact;
    pub mod strcasestr;
    pub mod strlcat;
    pub mod strlcpy;
    pub mod strmode;
    pub mod strndup;
    pub mod strnlen;
    pub mod strptime;
    pub mod strsep;
    pub mod strtoll;
    pub mod strtonum;
    pub mod strtoul;
    pub mod strtoull;
    pub mod timingsafe_bcmp;
    pub mod vis;
    pub mod xcrypt;
} // mod openbsd_compat
pub mod r#match;
pub mod packet;
pub mod platform;
pub mod platform_misc;
pub mod platform_pledge;
pub mod platform_tracing;
pub mod poly1305;
pub mod progressmeter;
pub mod readconf;
pub mod readpass;
pub mod rijndael;
pub mod sandbox_capsicum;
pub mod sandbox_darwin;
pub mod sandbox_null;
pub mod sandbox_pledge;
pub mod sandbox_rlimit;
pub mod sandbox_seccomp_filter;
pub mod sandbox_solaris;
pub mod sandbox_systrace;
pub mod scp;
pub mod servconf;
pub mod serverloop;
pub mod session;
pub mod sftp;
pub mod sftp_client;
pub mod sftp_common;
pub mod sftp_glob;
pub mod sftp_realpath;
pub mod sftp_server;
pub mod sftp_server_main;
pub mod sftp_usergroup;
pub mod sk_usbhid;
pub mod smult_curve25519_ref;
pub mod sntrup761;
pub mod srclimit;
pub mod ssh;
pub mod ssh_add;
pub mod ssh_agent;
pub mod ssh_api;
pub mod ssh_dss;
pub mod ssh_ecdsa;
pub mod ssh_ecdsa_sk;
pub mod ssh_ed25519;
pub mod ssh_ed25519_sk;
pub mod ssh_keygen;
pub mod ssh_keyscan;
pub mod ssh_keysign;
pub mod ssh_pkcs11;
pub mod ssh_pkcs11_helper;
pub mod ssh_rsa;
pub mod ssh_sk;
pub mod ssh_sk_client;
pub mod ssh_sk_helper;
pub mod ssh_xmss;
pub mod sshbuf;
pub mod sshbuf_getput_basic;
pub mod sshbuf_getput_crypto;
pub mod sshbuf_io;
pub mod sshbuf_misc;
pub mod sshconnect;
pub mod sshconnect2;
pub mod sshd;
pub mod ssherr;
pub mod sshkey;
pub mod sshkey_xmss;
pub mod sshlogin;
pub mod sshpty;
pub mod sshsig;
pub mod sshtty;
pub mod ttymodes;
pub mod uidswap;
pub mod umac;
pub mod umac128;
pub mod utf8;
pub mod xmalloc;
pub mod xmss_commons;
pub mod xmss_fast;
pub mod xmss_hash;
pub mod xmss_hash_address;
pub mod xmss_wots;
