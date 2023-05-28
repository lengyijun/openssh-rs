use ::libc;
extern "C" {
    pub type sshbuf;
    pub type bignum_st;
    pub type bignum_ctx;
    pub type evp_pkey_st;
    pub type dsa_st;
    pub type rsa_st;
    pub type rsa_meth_st;
    pub type ec_key_st;
    pub type ec_key_method_st;
    pub type x509_st;
    pub type X509_name_st;
    pub type ossl_lib_ctx_st;
    pub type stack_st_void;
    pub type ec_group_st;
    pub type ECDSA_SIG_st;
    fn freezero(_: *mut libc::c_void, _: size_t);

    fn memcpy(_: *mut libc::c_void, _: *const libc::c_void, _: libc::c_ulong) -> *mut libc::c_void;
    fn memset(__s: *mut libc::c_void, __c: libc::c_int, __n: size_t) -> *mut libc::c_void;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn dlopen(__file: *const libc::c_char, __mode: libc::c_int) -> *mut libc::c_void;
    fn dlclose(__handle: *mut libc::c_void) -> libc::c_int;
    fn dlsym(__handle: *mut libc::c_void, __name: *const libc::c_char) -> *mut libc::c_void;
    fn dlerror() -> *mut libc::c_char;
    fn CRYPTO_get_ex_new_index(
        class_index: libc::c_int,
        argl: libc::c_long,
        argp: *mut libc::c_void,
        new_func: Option<CRYPTO_EX_new>,
        dup_func: Option<CRYPTO_EX_dup>,
        free_func: Option<CRYPTO_EX_free>,
    ) -> libc::c_int;
    fn BN_bin2bn(s: *const libc::c_uchar, len: libc::c_int, ret: *mut BIGNUM) -> *mut BIGNUM;
    fn BN_free(a: *mut BIGNUM);
    fn ASN1_OCTET_STRING_free(a: *mut ASN1_OCTET_STRING);
    fn d2i_ASN1_OCTET_STRING(
        a: *mut *mut ASN1_OCTET_STRING,
        in_0: *mut *const libc::c_uchar,
        len: libc::c_long,
    ) -> *mut ASN1_OCTET_STRING;

    fn EVP_PKEY_get_base_id(pkey: *const EVP_PKEY) -> libc::c_int;
    fn EVP_PKEY_get0_RSA(pkey: *const EVP_PKEY) -> *const rsa_st;
    fn EVP_PKEY_get0_EC_KEY(pkey: *const EVP_PKEY) -> *const ec_key_st;
    fn RSA_new() -> *mut RSA;
    fn RSA_size(rsa: *const RSA) -> libc::c_int;
    fn RSA_set0_key(r: *mut RSA, n: *mut BIGNUM, e: *mut BIGNUM, d: *mut BIGNUM) -> libc::c_int;
    fn RSA_free(r: *mut RSA);
    fn RSA_get_default_method() -> *const RSA_METHOD;
    fn RSA_set_method(rsa: *mut RSA, meth: *const RSA_METHOD) -> libc::c_int;
    fn RSA_set_ex_data(r: *mut RSA, idx: libc::c_int, arg: *mut libc::c_void) -> libc::c_int;
    fn RSA_get_ex_data(r: *const RSA, idx: libc::c_int) -> *mut libc::c_void;
    fn RSAPublicKey_dup(a: *const RSA) -> *mut RSA;
    fn RSA_meth_dup(meth: *const RSA_METHOD) -> *mut RSA_METHOD;
    fn RSA_meth_set1_name(meth: *mut RSA_METHOD, name: *const libc::c_char) -> libc::c_int;
    fn RSA_meth_set_priv_enc(
        rsa: *mut RSA_METHOD,
        priv_enc: Option<
            unsafe extern "C" fn(
                libc::c_int,
                *const libc::c_uchar,
                *mut libc::c_uchar,
                *mut RSA,
                libc::c_int,
            ) -> libc::c_int,
        >,
    ) -> libc::c_int;
    fn RSA_meth_set_priv_dec(
        rsa: *mut RSA_METHOD,
        priv_dec: Option<
            unsafe extern "C" fn(
                libc::c_int,
                *const libc::c_uchar,
                *mut libc::c_uchar,
                *mut RSA,
                libc::c_int,
            ) -> libc::c_int,
        >,
    ) -> libc::c_int;
    fn ECDSA_SIG_set0(sig: *mut ECDSA_SIG, r: *mut BIGNUM, s: *mut BIGNUM) -> libc::c_int;
    fn EC_GROUP_free(group: *mut EC_GROUP);
    fn d2i_ECPKParameters(
        _: *mut *mut EC_GROUP,
        in_0: *mut *const libc::c_uchar,
        len: libc::c_long,
    ) -> *mut EC_GROUP;
    fn EC_KEY_new() -> *mut EC_KEY;
    fn EC_KEY_free(key: *mut EC_KEY);
    fn EC_KEY_dup(src: *const EC_KEY) -> *mut EC_KEY;
    fn EC_KEY_set_group(key: *mut EC_KEY, group: *const EC_GROUP) -> libc::c_int;
    fn EC_KEY_set_ex_data(
        key: *mut EC_KEY,
        idx: libc::c_int,
        arg: *mut libc::c_void,
    ) -> libc::c_int;
    fn EC_KEY_get_ex_data(key: *const EC_KEY, idx: libc::c_int) -> *mut libc::c_void;
    fn o2i_ECPublicKey(
        key: *mut *mut EC_KEY,
        in_0: *mut *const libc::c_uchar,
        len: libc::c_long,
    ) -> *mut EC_KEY;
    fn EC_KEY_OpenSSL() -> *const EC_KEY_METHOD;
    fn EC_KEY_set_method(key: *mut EC_KEY, meth: *const EC_KEY_METHOD) -> libc::c_int;
    fn ECDSA_SIG_new() -> *mut ECDSA_SIG;
    fn ECDSA_SIG_free(sig: *mut ECDSA_SIG);
    fn EC_KEY_METHOD_get_sign(
        meth: *const EC_KEY_METHOD,
        psign: *mut Option<
            unsafe extern "C" fn(
                libc::c_int,
                *const libc::c_uchar,
                libc::c_int,
                *mut libc::c_uchar,
                *mut libc::c_uint,
                *const BIGNUM,
                *const BIGNUM,
                *mut EC_KEY,
            ) -> libc::c_int,
        >,
        psign_setup: *mut Option<
            unsafe extern "C" fn(
                *mut EC_KEY,
                *mut BN_CTX,
                *mut *mut BIGNUM,
                *mut *mut BIGNUM,
            ) -> libc::c_int,
        >,
        psign_sig: *mut Option<
            unsafe extern "C" fn(
                *const libc::c_uchar,
                libc::c_int,
                *const BIGNUM,
                *const BIGNUM,
                *mut EC_KEY,
            ) -> *mut ECDSA_SIG,
        >,
    );
    fn ECDSA_size(eckey: *const EC_KEY) -> libc::c_int;
    fn EC_KEY_METHOD_new(meth: *const EC_KEY_METHOD) -> *mut EC_KEY_METHOD;
    fn EC_KEY_METHOD_set_sign(
        meth: *mut EC_KEY_METHOD,
        sign: Option<
            unsafe extern "C" fn(
                libc::c_int,
                *const libc::c_uchar,
                libc::c_int,
                *mut libc::c_uchar,
                *mut libc::c_uint,
                *const BIGNUM,
                *const BIGNUM,
                *mut EC_KEY,
            ) -> libc::c_int,
        >,
        sign_setup: Option<
            unsafe extern "C" fn(
                *mut EC_KEY,
                *mut BN_CTX,
                *mut *mut BIGNUM,
                *mut *mut BIGNUM,
            ) -> libc::c_int,
        >,
        sign_sig: Option<
            unsafe extern "C" fn(
                *const libc::c_uchar,
                libc::c_int,
                *const BIGNUM,
                *const BIGNUM,
                *mut EC_KEY,
            ) -> *mut ECDSA_SIG,
        >,
    );
    fn X509_NAME_free(a: *mut X509_NAME);
    fn d2i_X509_NAME(
        a: *mut *mut X509_NAME,
        in_0: *mut *const libc::c_uchar,
        len: libc::c_long,
    ) -> *mut X509_NAME;
    fn X509_free(a: *mut X509);
    fn d2i_X509(a: *mut *mut X509, in_0: *mut *const libc::c_uchar, len: libc::c_long)
        -> *mut X509;
    fn X509_NAME_oneline(
        a: *const X509_NAME,
        buf: *mut libc::c_char,
        size: libc::c_int,
    ) -> *mut libc::c_char;
    fn X509_get_pubkey(x: *mut X509) -> *mut EVP_PKEY;
    fn ERR_get_error() -> libc::c_ulong;
    fn ERR_error_string(e: libc::c_ulong, buf: *mut libc::c_char) -> *mut libc::c_char;

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
    fn read_passphrase(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
    fn sshkey_new(_: libc::c_int) -> *mut sshkey;
    fn sshkey_free(_: *mut sshkey);
    fn sshkey_equal(_: *const sshkey, _: *const sshkey) -> libc::c_int;
    fn sshkey_fingerprint(_: *const sshkey, _: libc::c_int, _: sshkey_fp_rep) -> *mut libc::c_char;
    fn sshkey_type(_: *const sshkey) -> *const libc::c_char;
    fn sshkey_ecdsa_key_to_nid(_: *mut EC_KEY) -> libc::c_int;
    fn xmalloc(_: size_t) -> *mut libc::c_void;
    fn xcalloc(_: size_t, _: size_t) -> *mut libc::c_void;
    fn xrecallocarray(_: *mut libc::c_void, _: size_t, _: size_t, _: size_t) -> *mut libc::c_void;

}
pub type __u_char = libc::c_uchar;
pub type __u_int = libc::c_uint;
pub type __u_long = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint64_t = libc::c_ulong;
pub type u_char = __u_char;
pub type u_int = __u_int;
pub type u_long = __u_long;
pub type size_t = libc::c_ulong;
pub type u_int64_t = __uint64_t;
pub type uint8_t = __uint8_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct asn1_string_st {
    pub length: libc::c_int,
    pub type_0: libc::c_int,
    pub data: *mut libc::c_uchar,
    pub flags: libc::c_long,
}
pub type ASN1_OCTET_STRING = asn1_string_st;
pub type BIGNUM = bignum_st;
pub type BN_CTX = bignum_ctx;
pub type EVP_PKEY = evp_pkey_st;
pub type DSA = dsa_st;
pub type RSA = rsa_st;
pub type RSA_METHOD = rsa_meth_st;
pub type EC_KEY = ec_key_st;
pub type EC_KEY_METHOD = ec_key_method_st;
pub type X509 = x509_st;
pub type X509_NAME = X509_name_st;
pub type OSSL_LIB_CTX = ossl_lib_ctx_st;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct crypto_ex_data_st {
    pub ctx: *mut OSSL_LIB_CTX,
    pub sk: *mut stack_st_void,
}
pub type CRYPTO_EX_DATA = crypto_ex_data_st;
pub type CRYPTO_EX_new = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_void,
    *mut CRYPTO_EX_DATA,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> ();
pub type CRYPTO_EX_free = unsafe extern "C" fn(
    *mut libc::c_void,
    *mut libc::c_void,
    *mut CRYPTO_EX_DATA,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> ();
pub type CRYPTO_EX_dup = unsafe extern "C" fn(
    *mut CRYPTO_EX_DATA,
    *const CRYPTO_EX_DATA,
    *mut *mut libc::c_void,
    libc::c_int,
    libc::c_long,
    *mut libc::c_void,
) -> libc::c_int;
pub type EC_GROUP = ec_group_st;
pub type ECDSA_SIG = ECDSA_SIG_st;
pub type CK_FLAGS = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _CK_VERSION {
    pub major: libc::c_uchar,
    pub minor: libc::c_uchar,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _CK_INFO {
    pub cryptokiVersion: _CK_VERSION,
    pub manufacturerID: [libc::c_uchar; 32],
    pub flags: CK_FLAGS,
    pub libraryDescription: [libc::c_uchar; 32],
    pub libraryVersion: _CK_VERSION,
}
pub type CK_NOTIFICATION = libc::c_ulong;
pub type CK_SLOT_ID = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _CK_SLOT_INFO {
    pub slotDescription: [libc::c_uchar; 64],
    pub manufacturerID: [libc::c_uchar; 32],
    pub flags: CK_FLAGS,
    pub hardwareVersion: _CK_VERSION,
    pub firmwareVersion: _CK_VERSION,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _CK_TOKEN_INFO {
    pub label: [libc::c_uchar; 32],
    pub manufacturerID: [libc::c_uchar; 32],
    pub model: [libc::c_uchar; 16],
    pub serialNumber: [libc::c_uchar; 16],
    pub flags: CK_FLAGS,
    pub ulMaxSessionCount: libc::c_ulong,
    pub ulSessionCount: libc::c_ulong,
    pub ulMaxRwSessionCount: libc::c_ulong,
    pub ulRwSessionCount: libc::c_ulong,
    pub ulMaxPinLen: libc::c_ulong,
    pub ulMinPinLen: libc::c_ulong,
    pub ulTotalPublicMemory: libc::c_ulong,
    pub ulFreePublicMemory: libc::c_ulong,
    pub ulTotalPrivateMemory: libc::c_ulong,
    pub ulFreePrivateMemory: libc::c_ulong,
    pub hardwareVersion: _CK_VERSION,
    pub firmwareVersion: _CK_VERSION,
    pub utcTime: [libc::c_uchar; 16],
}
pub type CK_SESSION_HANDLE = libc::c_ulong;
pub type CK_USER_TYPE = libc::c_ulong;
pub type CK_STATE = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _CK_SESSION_INFO {
    pub slotID: CK_SLOT_ID,
    pub state: CK_STATE,
    pub flags: CK_FLAGS,
    pub ulDeviceError: libc::c_ulong,
}
pub type CK_OBJECT_HANDLE = libc::c_ulong;
pub type CK_OBJECT_CLASS = libc::c_ulong;
pub type CK_KEY_TYPE = libc::c_ulong;
pub type CK_CERTIFICATE_TYPE = libc::c_ulong;
pub type CK_ATTRIBUTE_TYPE = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _CK_ATTRIBUTE {
    pub type_0: CK_ATTRIBUTE_TYPE,
    pub pValue: *mut libc::c_void,
    pub ulValueLen: libc::c_ulong,
}
pub type CK_MECHANISM_TYPE = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _CK_MECHANISM {
    pub mechanism: CK_MECHANISM_TYPE,
    pub pParameter: *mut libc::c_void,
    pub ulParameterLen: libc::c_ulong,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _CK_MECHANISM_INFO {
    pub ulMinKeySize: libc::c_ulong,
    pub ulMaxKeySize: libc::c_ulong,
    pub flags: CK_FLAGS,
}
pub type CK_RV = libc::c_ulong;
pub type CK_NOTIFY =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_NOTIFICATION, *mut libc::c_void) -> CK_RV>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _CK_FUNCTION_LIST {
    pub version: _CK_VERSION,
    pub C_Initialize: CK_C_Initialize,
    pub C_Finalize: CK_C_Finalize,
    pub C_GetInfo: CK_C_GetInfo,
    pub C_GetFunctionList: CK_C_GetFunctionList,
    pub C_GetSlotList: CK_C_GetSlotList,
    pub C_GetSlotInfo: CK_C_GetSlotInfo,
    pub C_GetTokenInfo: CK_C_GetTokenInfo,
    pub C_GetMechanismList: CK_C_GetMechanismList,
    pub C_GetMechanismInfo: CK_C_GetMechanismInfo,
    pub C_InitToken: CK_C_InitToken,
    pub C_InitPIN: CK_C_InitPIN,
    pub C_SetPIN: CK_C_SetPIN,
    pub C_OpenSession: CK_C_OpenSession,
    pub C_CloseSession: CK_C_CloseSession,
    pub C_CloseAllSessions: CK_C_CloseAllSessions,
    pub C_GetSessionInfo: CK_C_GetSessionInfo,
    pub C_GetOperationState: CK_C_GetOperationState,
    pub C_SetOperationState: CK_C_SetOperationState,
    pub C_Login: CK_C_Login,
    pub C_Logout: CK_C_Logout,
    pub C_CreateObject: CK_C_CreateObject,
    pub C_CopyObject: CK_C_CopyObject,
    pub C_DestroyObject: CK_C_DestroyObject,
    pub C_GetObjectSize: CK_C_GetObjectSize,
    pub C_GetAttributeValue: CK_C_GetAttributeValue,
    pub C_SetAttributeValue: CK_C_SetAttributeValue,
    pub C_FindObjectsInit: CK_C_FindObjectsInit,
    pub C_FindObjects: CK_C_FindObjects,
    pub C_FindObjectsFinal: CK_C_FindObjectsFinal,
    pub C_EncryptInit: CK_C_EncryptInit,
    pub C_Encrypt: CK_C_Encrypt,
    pub C_EncryptUpdate: CK_C_EncryptUpdate,
    pub C_EncryptFinal: CK_C_EncryptFinal,
    pub C_DecryptInit: CK_C_DecryptInit,
    pub C_Decrypt: CK_C_Decrypt,
    pub C_DecryptUpdate: CK_C_DecryptUpdate,
    pub C_DecryptFinal: CK_C_DecryptFinal,
    pub C_DigestInit: CK_C_DigestInit,
    pub C_Digest: CK_C_Digest,
    pub C_DigestUpdate: CK_C_DigestUpdate,
    pub C_DigestKey: CK_C_DigestKey,
    pub C_DigestFinal: CK_C_DigestFinal,
    pub C_SignInit: CK_C_SignInit,
    pub C_Sign: CK_C_Sign,
    pub C_SignUpdate: CK_C_SignUpdate,
    pub C_SignFinal: CK_C_SignFinal,
    pub C_SignRecoverInit: CK_C_SignRecoverInit,
    pub C_SignRecover: CK_C_SignRecover,
    pub C_VerifyInit: CK_C_VerifyInit,
    pub C_Verify: CK_C_Verify,
    pub C_VerifyUpdate: CK_C_VerifyUpdate,
    pub C_VerifyFinal: CK_C_VerifyFinal,
    pub C_VerifyRecoverInit: CK_C_VerifyRecoverInit,
    pub C_VerifyRecover: CK_C_VerifyRecover,
    pub C_DigestEncryptUpdate: CK_C_DigestEncryptUpdate,
    pub C_DecryptDigestUpdate: CK_C_DecryptDigestUpdate,
    pub C_SignEncryptUpdate: CK_C_SignEncryptUpdate,
    pub C_DecryptVerifyUpdate: CK_C_DecryptVerifyUpdate,
    pub C_GenerateKey: CK_C_GenerateKey,
    pub C_GenerateKeyPair: CK_C_GenerateKeyPair,
    pub C_WrapKey: CK_C_WrapKey,
    pub C_UnwrapKey: CK_C_UnwrapKey,
    pub C_DeriveKey: CK_C_DeriveKey,
    pub C_SeedRandom: CK_C_SeedRandom,
    pub C_GenerateRandom: CK_C_GenerateRandom,
    pub C_GetFunctionStatus: CK_C_GetFunctionStatus,
    pub C_CancelFunction: CK_C_CancelFunction,
    pub C_WaitForSlotEvent: CK_C_WaitForSlotEvent,
}
pub type CK_C_WaitForSlotEvent =
    Option<unsafe extern "C" fn(CK_FLAGS, *mut CK_SLOT_ID, *mut libc::c_void) -> CK_RV>;
pub type CK_C_CancelFunction = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_GetFunctionStatus = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_GenerateRandom =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut libc::c_uchar, libc::c_ulong) -> CK_RV>;
pub type CK_C_SeedRandom =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut libc::c_uchar, libc::c_ulong) -> CK_RV>;
pub type CK_C_DeriveKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut _CK_MECHANISM,
        CK_OBJECT_HANDLE,
        *mut _CK_ATTRIBUTE,
        libc::c_ulong,
        *mut CK_OBJECT_HANDLE,
    ) -> CK_RV,
>;
pub type CK_C_UnwrapKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut _CK_MECHANISM,
        CK_OBJECT_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut _CK_ATTRIBUTE,
        libc::c_ulong,
        *mut CK_OBJECT_HANDLE,
    ) -> CK_RV,
>;
pub type CK_C_WrapKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut _CK_MECHANISM,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
        *mut libc::c_uchar,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_GenerateKeyPair = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut _CK_MECHANISM,
        *mut _CK_ATTRIBUTE,
        libc::c_ulong,
        *mut _CK_ATTRIBUTE,
        libc::c_ulong,
        *mut CK_OBJECT_HANDLE,
        *mut CK_OBJECT_HANDLE,
    ) -> CK_RV,
>;
pub type CK_C_GenerateKey = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut _CK_MECHANISM,
        *mut _CK_ATTRIBUTE,
        libc::c_ulong,
        *mut CK_OBJECT_HANDLE,
    ) -> CK_RV,
>;
pub type CK_C_DecryptVerifyUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_SignEncryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_DecryptDigestUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_DigestEncryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_VerifyRecover = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_VerifyRecoverInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut _CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_VerifyFinal =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut libc::c_uchar, libc::c_ulong) -> CK_RV>;
pub type CK_C_VerifyUpdate =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut libc::c_uchar, libc::c_ulong) -> CK_RV>;
pub type CK_C_Verify = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_VerifyInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut _CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_SignRecover = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_SignRecoverInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut _CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_SignFinal = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut libc::c_uchar, *mut libc::c_ulong) -> CK_RV,
>;
pub type CK_C_SignUpdate =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut libc::c_uchar, libc::c_ulong) -> CK_RV>;
pub type CK_C_Sign = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_SignInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut _CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_DigestFinal = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut libc::c_uchar, *mut libc::c_ulong) -> CK_RV,
>;
pub type CK_C_DigestKey =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_DigestUpdate =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut libc::c_uchar, libc::c_ulong) -> CK_RV>;
pub type CK_C_Digest = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_DigestInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut _CK_MECHANISM) -> CK_RV>;
pub type CK_C_DecryptFinal = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut libc::c_uchar, *mut libc::c_ulong) -> CK_RV,
>;
pub type CK_C_DecryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_Decrypt = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_DecryptInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut _CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_EncryptFinal = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut libc::c_uchar, *mut libc::c_ulong) -> CK_RV,
>;
pub type CK_C_EncryptUpdate = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_Encrypt = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_EncryptInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut _CK_MECHANISM, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_FindObjectsFinal = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_FindObjects = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut CK_OBJECT_HANDLE,
        libc::c_ulong,
        *mut libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_FindObjectsInit =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut _CK_ATTRIBUTE, libc::c_ulong) -> CK_RV>;
pub type CK_C_SetAttributeValue = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        *mut _CK_ATTRIBUTE,
        libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_GetAttributeValue = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        *mut _CK_ATTRIBUTE,
        libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_GetObjectSize =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, *mut libc::c_ulong) -> CK_RV>;
pub type CK_C_DestroyObject =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, CK_OBJECT_HANDLE) -> CK_RV>;
pub type CK_C_CopyObject = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_OBJECT_HANDLE,
        *mut _CK_ATTRIBUTE,
        libc::c_ulong,
        *mut CK_OBJECT_HANDLE,
    ) -> CK_RV,
>;
pub type CK_C_CreateObject = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut _CK_ATTRIBUTE,
        libc::c_ulong,
        *mut CK_OBJECT_HANDLE,
    ) -> CK_RV,
>;
pub type CK_C_Logout = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_Login = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        CK_USER_TYPE,
        *mut libc::c_uchar,
        libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_SetOperationState = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        CK_OBJECT_HANDLE,
        CK_OBJECT_HANDLE,
    ) -> CK_RV,
>;
pub type CK_C_GetOperationState = Option<
    unsafe extern "C" fn(CK_SESSION_HANDLE, *mut libc::c_uchar, *mut libc::c_ulong) -> CK_RV,
>;
pub type CK_C_GetSessionInfo =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut _CK_SESSION_INFO) -> CK_RV>;
pub type CK_C_CloseAllSessions = Option<unsafe extern "C" fn(CK_SLOT_ID) -> CK_RV>;
pub type CK_C_CloseSession = Option<unsafe extern "C" fn(CK_SESSION_HANDLE) -> CK_RV>;
pub type CK_C_OpenSession = Option<
    unsafe extern "C" fn(
        CK_SLOT_ID,
        CK_FLAGS,
        *mut libc::c_void,
        CK_NOTIFY,
        *mut CK_SESSION_HANDLE,
    ) -> CK_RV,
>;
pub type CK_C_SetPIN = Option<
    unsafe extern "C" fn(
        CK_SESSION_HANDLE,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
        libc::c_ulong,
    ) -> CK_RV,
>;
pub type CK_C_InitPIN =
    Option<unsafe extern "C" fn(CK_SESSION_HANDLE, *mut libc::c_uchar, libc::c_ulong) -> CK_RV>;
pub type CK_C_InitToken = Option<
    unsafe extern "C" fn(
        CK_SLOT_ID,
        *mut libc::c_uchar,
        libc::c_ulong,
        *mut libc::c_uchar,
    ) -> CK_RV,
>;
pub type CK_C_GetMechanismInfo =
    Option<unsafe extern "C" fn(CK_SLOT_ID, CK_MECHANISM_TYPE, *mut _CK_MECHANISM_INFO) -> CK_RV>;
pub type CK_C_GetMechanismList =
    Option<unsafe extern "C" fn(CK_SLOT_ID, *mut CK_MECHANISM_TYPE, *mut libc::c_ulong) -> CK_RV>;
pub type CK_C_GetTokenInfo = Option<unsafe extern "C" fn(CK_SLOT_ID, *mut _CK_TOKEN_INFO) -> CK_RV>;
pub type CK_C_GetSlotInfo = Option<unsafe extern "C" fn(CK_SLOT_ID, *mut _CK_SLOT_INFO) -> CK_RV>;
pub type CK_C_GetSlotList =
    Option<unsafe extern "C" fn(libc::c_uchar, *mut CK_SLOT_ID, *mut libc::c_ulong) -> CK_RV>;
pub type CK_C_GetFunctionList = Option<unsafe extern "C" fn(*mut *mut _CK_FUNCTION_LIST) -> CK_RV>;
pub type CK_C_GetInfo = Option<unsafe extern "C" fn(*mut _CK_INFO) -> CK_RV>;
pub type CK_C_Finalize = Option<unsafe extern "C" fn(*mut libc::c_void) -> CK_RV>;
pub type CK_C_Initialize = Option<unsafe extern "C" fn(*mut libc::c_void) -> CK_RV>;
pub type CK_BYTE = libc::c_uchar;
pub type CK_UTF8CHAR = libc::c_uchar;
pub type CK_BBOOL = libc::c_uchar;
pub type CK_ULONG = libc::c_ulong;
pub type CK_INFO = _CK_INFO;
pub type CK_TOKEN_INFO = _CK_TOKEN_INFO;
pub type CK_ATTRIBUTE = _CK_ATTRIBUTE;
pub type CK_MECHANISM = _CK_MECHANISM;
pub type CK_FUNCTION_LIST = _CK_FUNCTION_LIST;
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
pub type sshkey_types = libc::c_uint;
pub const KEY_UNSPEC: sshkey_types = 14;
pub const KEY_ED25519_SK_CERT: sshkey_types = 13;
pub const KEY_ED25519_SK: sshkey_types = 12;
pub const KEY_ECDSA_SK_CERT: sshkey_types = 11;
pub const KEY_ECDSA_SK: sshkey_types = 10;
pub const KEY_XMSS_CERT: sshkey_types = 9;
pub const KEY_XMSS: sshkey_types = 8;
pub const KEY_ED25519_CERT: sshkey_types = 7;
pub const KEY_ECDSA_CERT: sshkey_types = 6;
pub const KEY_DSA_CERT: sshkey_types = 5;
pub const KEY_RSA_CERT: sshkey_types = 4;
pub const KEY_ED25519: sshkey_types = 3;
pub const KEY_ECDSA: sshkey_types = 2;
pub const KEY_DSA: sshkey_types = 1;
pub const KEY_RSA: sshkey_types = 0;
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
pub struct pkcs11_provider {
    pub name: *mut libc::c_char,
    pub handle: *mut libc::c_void,
    pub function_list: *mut CK_FUNCTION_LIST,
    pub info: CK_INFO,
    pub nslots: CK_ULONG,
    pub slotlist: *mut CK_SLOT_ID,
    pub slotinfo: *mut pkcs11_slotinfo,
    pub valid: libc::c_int,
    pub refcount: libc::c_int,
    pub next: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed {
    pub tqe_next: *mut pkcs11_provider,
    pub tqe_prev: *mut *mut pkcs11_provider,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs11_slotinfo {
    pub token: CK_TOKEN_INFO,
    pub session: CK_SESSION_HANDLE,
    pub logged_in: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub tqh_first: *mut pkcs11_provider,
    pub tqh_last: *mut *mut pkcs11_provider,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct pkcs11_key {
    pub provider: *mut pkcs11_provider,
    pub slotidx: CK_ULONG,
    pub keyid: *mut libc::c_char,
    pub keyid_len: libc::c_int,
}
pub static mut pkcs11_providers: C2RustUnnamed_0 = C2RustUnnamed_0 {
    tqh_first: 0 as *const pkcs11_provider as *mut pkcs11_provider,
    tqh_last: 0 as *const *mut pkcs11_provider as *mut *mut pkcs11_provider,
};
pub static mut pkcs11_interactive: libc::c_int = 0 as libc::c_int;
unsafe extern "C" fn ossl_error(mut msg: *const libc::c_char) {
    let mut e: libc::c_ulong = 0;
    crate::log::sshlog(
        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"ossl_error\0")).as_ptr(),
        88 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_ERROR,
        0 as *const libc::c_char,
        b"%s\0" as *const u8 as *const libc::c_char,
        msg,
    );
    loop {
        e = ERR_get_error();
        if !(e != 0 as libc::c_int as libc::c_ulong) {
            break;
        }
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 11], &[libc::c_char; 11]>(b"ossl_error\0")).as_ptr(),
            90 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"libcrypto error: %s\0" as *const u8 as *const libc::c_char,
            ERR_error_string(e, 0 as *mut libc::c_char),
        );
    }
}
pub unsafe extern "C" fn pkcs11_init(mut interactive: libc::c_int) -> libc::c_int {
    pkcs11_interactive = interactive;
    pkcs11_providers.tqh_first = 0 as *mut pkcs11_provider;
    pkcs11_providers.tqh_last = &mut pkcs11_providers.tqh_first;
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkcs11_provider_finalize(mut p: *mut pkcs11_provider) {
    let mut rv: CK_RV = 0;
    let mut i: CK_ULONG = 0;
    crate::log::sshlog(
        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(b"pkcs11_provider_finalize\0"))
            .as_ptr(),
        115 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"provider \"%s\" refcount %d valid %d\0" as *const u8 as *const libc::c_char,
        (*p).name,
        (*p).refcount,
        (*p).valid,
    );
    if (*p).valid == 0 {
        return;
    }
    i = 0 as libc::c_int as CK_ULONG;
    while i < (*p).nslots {
        if (*((*p).slotinfo).offset(i as isize)).session != 0 && {
            rv = ((*(*p).function_list).C_CloseSession).expect("non-null function pointer")(
                (*((*p).slotinfo).offset(i as isize)).session,
            );
            rv != 0 as libc::c_int as libc::c_ulong
        } {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"pkcs11_provider_finalize\0",
                ))
                .as_ptr(),
                122 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"C_CloseSession failed: %lu\0" as *const u8 as *const libc::c_char,
                rv,
            );
        }
        i = i.wrapping_add(1);
        i;
    }
    rv = ((*(*p).function_list).C_Finalize).expect("non-null function pointer")(
        0 as *mut libc::c_void,
    );
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"pkcs11_provider_finalize\0",
            ))
            .as_ptr(),
            125 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_Finalize failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
    }
    (*p).valid = 0 as libc::c_int;
    (*p).function_list = 0 as *mut CK_FUNCTION_LIST;
    dlclose((*p).handle);
}
unsafe extern "C" fn pkcs11_provider_unref(mut p: *mut pkcs11_provider) {
    crate::log::sshlog(
        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(b"pkcs11_provider_unref\0"))
            .as_ptr(),
        138 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"provider \"%s\" refcount %d\0" as *const u8 as *const libc::c_char,
        (*p).name,
        (*p).refcount,
    );
    (*p).refcount -= 1;
    if (*p).refcount <= 0 as libc::c_int {
        if (*p).valid != 0 {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 22], &[libc::c_char; 22]>(
                    b"pkcs11_provider_unref\0",
                ))
                .as_ptr(),
                141 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"provider \"%s\" still valid\0" as *const u8 as *const libc::c_char,
                (*p).name,
            );
        }
        libc::free((*p).name as *mut libc::c_void);
        libc::free((*p).slotlist as *mut libc::c_void);
        libc::free((*p).slotinfo as *mut libc::c_void);
        libc::free(p as *mut libc::c_void);
    }
}
pub unsafe extern "C" fn pkcs11_terminate() {
    let mut p: *mut pkcs11_provider = 0 as *mut pkcs11_provider;
    loop {
        p = pkcs11_providers.tqh_first;
        if p.is_null() {
            break;
        }
        if !((*p).next.tqe_next).is_null() {
            (*(*p).next.tqe_next).next.tqe_prev = (*p).next.tqe_prev;
        } else {
            pkcs11_providers.tqh_last = (*p).next.tqe_prev;
        }
        *(*p).next.tqe_prev = (*p).next.tqe_next;
        pkcs11_provider_finalize(p);
        pkcs11_provider_unref(p);
    }
}
unsafe extern "C" fn pkcs11_provider_lookup(
    mut provider_id: *mut libc::c_char,
) -> *mut pkcs11_provider {
    let mut p: *mut pkcs11_provider = 0 as *mut pkcs11_provider;
    p = pkcs11_providers.tqh_first;
    while !p.is_null() {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 23], &[libc::c_char; 23]>(
                b"pkcs11_provider_lookup\0",
            ))
            .as_ptr(),
            169 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"check provider \"%s\"\0" as *const u8 as *const libc::c_char,
            (*p).name,
        );
        if strcmp(provider_id, (*p).name) == 0 {
            return p;
        }
        p = (*p).next.tqe_next;
    }
    return 0 as *mut pkcs11_provider;
}
pub unsafe extern "C" fn pkcs11_del_provider(mut provider_id: *mut libc::c_char) -> libc::c_int {
    let mut p: *mut pkcs11_provider = 0 as *mut pkcs11_provider;
    p = pkcs11_provider_lookup(provider_id);
    if !p.is_null() {
        if !((*p).next.tqe_next).is_null() {
            (*(*p).next.tqe_next).next.tqe_prev = (*p).next.tqe_prev;
        } else {
            pkcs11_providers.tqh_last = (*p).next.tqe_prev;
        }
        *(*p).next.tqe_prev = (*p).next.tqe_next;
        pkcs11_provider_finalize(p);
        pkcs11_provider_unref(p);
        return 0 as libc::c_int;
    }
    return -(1 as libc::c_int);
}
static mut rsa_method: *mut RSA_METHOD = 0 as *const RSA_METHOD as *mut RSA_METHOD;
static mut rsa_idx: libc::c_int = 0 as libc::c_int;
static mut ec_key_method: *mut EC_KEY_METHOD = 0 as *const EC_KEY_METHOD as *mut EC_KEY_METHOD;
static mut ec_key_idx: libc::c_int = 0 as libc::c_int;
unsafe extern "C" fn pkcs11_k11_free(
    mut parent: *mut libc::c_void,
    mut ptr: *mut libc::c_void,
    mut _ad: *mut CRYPTO_EX_DATA,
    mut idx: libc::c_int,
    mut _argl: libc::c_long,
    mut _argp: *mut libc::c_void,
) {
    let mut k11: *mut pkcs11_key = ptr as *mut pkcs11_key;
    crate::log::sshlog(
        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 16], &[libc::c_char; 16]>(b"pkcs11_k11_free\0")).as_ptr(),
        205 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"parent %p ptr %p idx %d\0" as *const u8 as *const libc::c_char,
        parent,
        ptr,
        idx,
    );
    if k11.is_null() {
        return;
    }
    if !((*k11).provider).is_null() {
        pkcs11_provider_unref((*k11).provider);
    }
    libc::free((*k11).keyid as *mut libc::c_void);
    libc::free(k11 as *mut libc::c_void);
}
unsafe extern "C" fn pkcs11_find(
    mut p: *mut pkcs11_provider,
    mut slotidx: CK_ULONG,
    mut attr: *mut CK_ATTRIBUTE,
    mut nattr: CK_ULONG,
    mut obj: *mut CK_OBJECT_HANDLE,
) -> libc::c_int {
    let mut f: *mut CK_FUNCTION_LIST = 0 as *mut CK_FUNCTION_LIST;
    let mut session: CK_SESSION_HANDLE = 0;
    let mut nfound: CK_ULONG = 0 as libc::c_int as CK_ULONG;
    let mut rv: CK_RV = 0;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    f = (*p).function_list;
    session = (*((*p).slotinfo).offset(slotidx as isize)).session;
    rv = ((*f).C_FindObjectsInit).expect("non-null function pointer")(session, attr, nattr);
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"pkcs11_find\0")).as_ptr(),
            228 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_FindObjectsInit failed (nattr %lu): %lu\0" as *const u8 as *const libc::c_char,
            nattr,
            rv,
        );
        return -(1 as libc::c_int);
    }
    rv = ((*f).C_FindObjects).expect("non-null function pointer")(
        session,
        obj,
        1 as libc::c_int as libc::c_ulong,
        &mut nfound,
    );
    if rv != 0 as libc::c_int as libc::c_ulong || nfound != 1 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"pkcs11_find\0")).as_ptr(),
            234 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"C_FindObjects failed (nfound %lu nattr %lu): %lu\0" as *const u8
                as *const libc::c_char,
            nfound,
            nattr,
            rv,
        );
    } else {
        ret = 0 as libc::c_int;
    }
    rv = ((*f).C_FindObjectsFinal).expect("non-null function pointer")(session);
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"pkcs11_find\0")).as_ptr(),
            238 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_FindObjectsFinal failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
    }
    return ret;
}
unsafe extern "C" fn pkcs11_login_slot(
    mut provider: *mut pkcs11_provider,
    mut si: *mut pkcs11_slotinfo,
    mut type_0: CK_USER_TYPE,
) -> libc::c_int {
    let mut pin: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut prompt: [libc::c_char; 1024] = [0; 1024];
    let mut rv: CK_RV = 0;
    if provider.is_null() || si.is_null() || (*provider).valid == 0 {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"pkcs11_login_slot\0"))
                .as_ptr(),
            250 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no pkcs11 (valid) provider found\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if pkcs11_interactive == 0 {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"pkcs11_login_slot\0"))
                .as_ptr(),
            257 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"need pin entry%s\0" as *const u8 as *const libc::c_char,
            if (*si).token.flags & ((1 as libc::c_int) << 8 as libc::c_int) as libc::c_ulong != 0 {
                b" on reader keypad\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
        );
        return -(1 as libc::c_int);
    }
    if (*si).token.flags & ((1 as libc::c_int) << 8 as libc::c_int) as libc::c_ulong != 0 {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"pkcs11_login_slot\0"))
                .as_ptr(),
            261 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_VERBOSE,
            0 as *const libc::c_char,
            b"Deferring PIN entry to reader keypad.\0" as *const u8 as *const libc::c_char,
        );
    } else {
        libc::snprintf(
            prompt.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 1024]>() as usize,
            b"Enter PIN for '%s': \0" as *const u8 as *const libc::c_char,
            ((*si).token.label).as_mut_ptr(),
        );
        pin = read_passphrase(prompt.as_mut_ptr(), 0x4 as libc::c_int);
        if pin.is_null() {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"pkcs11_login_slot\0"))
                    .as_ptr(),
                266 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"no pin specified\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
    }
    rv = ((*(*provider).function_list).C_Login).expect("non-null function pointer")(
        (*si).session,
        type_0,
        pin as *mut u_char,
        if !pin.is_null() {
            strlen(pin)
        } else {
            0 as libc::c_int as libc::c_ulong
        },
    );
    if !pin.is_null() {
        freezero(pin as *mut libc::c_void, strlen(pin));
    }
    match rv {
        0 | 256 => {}
        162 => {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"pkcs11_login_slot\0"))
                    .as_ptr(),
                281 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"PKCS#11 login failed: PIN length out of range\0" as *const u8
                    as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        160 => {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"pkcs11_login_slot\0"))
                    .as_ptr(),
                284 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"PKCS#11 login failed: PIN incorrect\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        164 => {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"pkcs11_login_slot\0"))
                    .as_ptr(),
                287 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"PKCS#11 login failed: PIN locked\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        _ => {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"pkcs11_login_slot\0"))
                    .as_ptr(),
                290 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"PKCS#11 login failed: error %lu\0" as *const u8 as *const libc::c_char,
                rv,
            );
            return -(1 as libc::c_int);
        }
    }
    (*si).logged_in = 1 as libc::c_int;
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkcs11_login(
    mut k11: *mut pkcs11_key,
    mut type_0: CK_USER_TYPE,
) -> libc::c_int {
    if k11.is_null() || ((*k11).provider).is_null() || (*(*k11).provider).valid == 0 {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 13], &[libc::c_char; 13]>(b"pkcs11_login\0")).as_ptr(),
            301 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no pkcs11 (valid) provider found\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    return pkcs11_login_slot(
        (*k11).provider,
        &mut *((*(*k11).provider).slotinfo).offset((*k11).slotidx as isize),
        type_0,
    );
}
unsafe extern "C" fn pkcs11_check_obj_bool_attrib(
    mut k11: *mut pkcs11_key,
    mut obj: CK_OBJECT_HANDLE,
    mut type_0: CK_ATTRIBUTE_TYPE,
    mut val: *mut libc::c_int,
) -> libc::c_int {
    let mut si: *mut pkcs11_slotinfo = 0 as *mut pkcs11_slotinfo;
    let mut f: *mut CK_FUNCTION_LIST = 0 as *mut CK_FUNCTION_LIST;
    let mut flag: CK_BBOOL = 0 as libc::c_int as CK_BBOOL;
    let mut attr: CK_ATTRIBUTE = CK_ATTRIBUTE {
        type_0: 0,
        pValue: 0 as *mut libc::c_void,
        ulValueLen: 0,
    };
    let mut rv: CK_RV = 0;
    *val = 0 as libc::c_int;
    if ((*k11).provider).is_null() || (*(*k11).provider).valid == 0 {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"pkcs11_check_obj_bool_attrib\0",
            ))
            .as_ptr(),
            323 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no pkcs11 (valid) provider found\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    f = (*(*k11).provider).function_list;
    si =
        &mut *((*(*k11).provider).slotinfo).offset((*k11).slotidx as isize) as *mut pkcs11_slotinfo;
    attr.type_0 = type_0;
    attr.pValue = &mut flag as *mut CK_BBOOL as *mut libc::c_void;
    attr.ulValueLen = ::core::mem::size_of::<CK_BBOOL>() as libc::c_ulong;
    rv = ((*f).C_GetAttributeValue).expect("non-null function pointer")(
        (*si).session,
        obj,
        &mut attr,
        1 as libc::c_int as libc::c_ulong,
    );
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
                b"pkcs11_check_obj_bool_attrib\0",
            ))
            .as_ptr(),
            336 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_GetAttributeValue failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
        return -(1 as libc::c_int);
    }
    *val = (flag as libc::c_int != 0 as libc::c_int) as libc::c_int;
    crate::log::sshlog(
        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 29], &[libc::c_char; 29]>(
            b"pkcs11_check_obj_bool_attrib\0",
        ))
        .as_ptr(),
        341 as libc::c_int,
        1 as libc::c_int,
        SYSLOG_LEVEL_DEBUG1,
        0 as *const libc::c_char,
        b"provider \"%s\" slot %lu object %lu: attrib %lu = %d\0" as *const u8
            as *const libc::c_char,
        (*(*k11).provider).name,
        (*k11).slotidx,
        obj,
        type_0,
        *val,
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkcs11_get_key(
    mut k11: *mut pkcs11_key,
    mut mech_type: CK_MECHANISM_TYPE,
) -> libc::c_int {
    let mut si: *mut pkcs11_slotinfo = 0 as *mut pkcs11_slotinfo;
    let mut f: *mut CK_FUNCTION_LIST = 0 as *mut CK_FUNCTION_LIST;
    let mut obj: CK_OBJECT_HANDLE = 0;
    let mut rv: CK_RV = 0;
    let mut private_key_class: CK_OBJECT_CLASS = 0;
    let mut true_val: CK_BBOOL = 0;
    let mut mech: CK_MECHANISM = CK_MECHANISM {
        mechanism: 0,
        pParameter: 0 as *mut libc::c_void,
        ulParameterLen: 0,
    };
    let mut key_filter: [CK_ATTRIBUTE; 3] = [CK_ATTRIBUTE {
        type_0: 0,
        pValue: 0 as *mut libc::c_void,
        ulValueLen: 0,
    }; 3];
    let mut always_auth: libc::c_int = 0 as libc::c_int;
    let mut did_login: libc::c_int = 0 as libc::c_int;
    if ((*k11).provider).is_null() || (*(*k11).provider).valid == 0 {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"pkcs11_get_key\0"))
                .as_ptr(),
            360 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"no pkcs11 (valid) provider found\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    f = (*(*k11).provider).function_list;
    si =
        &mut *((*(*k11).provider).slotinfo).offset((*k11).slotidx as isize) as *mut pkcs11_slotinfo;
    if (*si).token.flags & ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_ulong != 0
        && (*si).logged_in == 0
    {
        if pkcs11_login(k11, 1 as libc::c_int as CK_USER_TYPE) < 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"pkcs11_get_key\0"))
                    .as_ptr(),
                369 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"login failed\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
        did_login = 1 as libc::c_int;
    }
    memset(
        &mut key_filter as *mut [CK_ATTRIBUTE; 3] as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[CK_ATTRIBUTE; 3]>() as libc::c_ulong,
    );
    private_key_class = 3 as libc::c_int as CK_OBJECT_CLASS;
    key_filter[0 as libc::c_int as usize].type_0 = 0 as libc::c_int as CK_ATTRIBUTE_TYPE;
    key_filter[0 as libc::c_int as usize].pValue =
        &mut private_key_class as *mut CK_OBJECT_CLASS as *mut libc::c_void;
    key_filter[0 as libc::c_int as usize].ulValueLen =
        ::core::mem::size_of::<CK_OBJECT_CLASS>() as libc::c_ulong;
    key_filter[1 as libc::c_int as usize].type_0 = 0x102 as libc::c_int as CK_ATTRIBUTE_TYPE;
    key_filter[1 as libc::c_int as usize].pValue = (*k11).keyid as *mut libc::c_void;
    key_filter[1 as libc::c_int as usize].ulValueLen = (*k11).keyid_len as libc::c_ulong;
    true_val = 1 as libc::c_int as CK_BBOOL;
    key_filter[2 as libc::c_int as usize].type_0 = 0x108 as libc::c_int as CK_ATTRIBUTE_TYPE;
    key_filter[2 as libc::c_int as usize].pValue =
        &mut true_val as *mut CK_BBOOL as *mut libc::c_void;
    key_filter[2 as libc::c_int as usize].ulValueLen =
        ::core::mem::size_of::<CK_BBOOL>() as libc::c_ulong;
    if pkcs11_find(
        (*k11).provider,
        (*k11).slotidx,
        key_filter.as_mut_ptr(),
        3 as libc::c_int as CK_ULONG,
        &mut obj,
    ) < 0 as libc::c_int
        && pkcs11_find(
            (*k11).provider,
            (*k11).slotidx,
            key_filter.as_mut_ptr(),
            2 as libc::c_int as CK_ULONG,
            &mut obj,
        ) < 0 as libc::c_int
    {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"pkcs11_get_key\0"))
                .as_ptr(),
            393 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"cannot find private key\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    memset(
        &mut mech as *mut CK_MECHANISM as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<CK_MECHANISM>() as libc::c_ulong,
    );
    mech.mechanism = mech_type;
    mech.pParameter = 0 as *mut libc::c_void;
    mech.ulParameterLen = 0 as libc::c_int as libc::c_ulong;
    rv = ((*f).C_SignInit).expect("non-null function pointer")((*si).session, &mut mech, obj);
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"pkcs11_get_key\0"))
                .as_ptr(),
            403 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_SignInit failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
        return -(1 as libc::c_int);
    }
    pkcs11_check_obj_bool_attrib(
        k11,
        obj,
        0x202 as libc::c_int as CK_ATTRIBUTE_TYPE,
        &mut always_auth,
    );
    if always_auth != 0 && did_login == 0 {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"pkcs11_get_key\0"))
                .as_ptr(),
            410 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"always-auth key\0" as *const u8 as *const libc::c_char,
        );
        if pkcs11_login(k11, 2 as libc::c_int as CK_USER_TYPE) < 0 as libc::c_int {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 15], &[libc::c_char; 15]>(b"pkcs11_get_key\0"))
                    .as_ptr(),
                412 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"login failed for always-auth key\0" as *const u8 as *const libc::c_char,
            );
            return -(1 as libc::c_int);
        }
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkcs11_rsa_private_encrypt(
    mut flen: libc::c_int,
    mut from: *const u_char,
    mut to: *mut u_char,
    mut rsa: *mut RSA,
    mut _padding: libc::c_int,
) -> libc::c_int {
    let mut k11: *mut pkcs11_key = 0 as *mut pkcs11_key;
    let mut si: *mut pkcs11_slotinfo = 0 as *mut pkcs11_slotinfo;
    let mut f: *mut CK_FUNCTION_LIST = 0 as *mut CK_FUNCTION_LIST;
    let mut tlen: CK_ULONG = 0 as libc::c_int as CK_ULONG;
    let mut rv: CK_RV = 0;
    let mut rval: libc::c_int = -(1 as libc::c_int);
    k11 = RSA_get_ex_data(rsa, rsa_idx) as *mut pkcs11_key;
    if k11.is_null() {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"pkcs11_rsa_private_encrypt\0",
            ))
            .as_ptr(),
            433 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"RSA_get_ex_data failed\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    if pkcs11_get_key(k11, 1 as libc::c_int as CK_MECHANISM_TYPE) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"pkcs11_rsa_private_encrypt\0",
            ))
            .as_ptr(),
            438 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"pkcs11_get_key failed\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    f = (*(*k11).provider).function_list;
    si =
        &mut *((*(*k11).provider).slotinfo).offset((*k11).slotidx as isize) as *mut pkcs11_slotinfo;
    tlen = RSA_size(rsa) as CK_ULONG;
    rv = ((*f).C_Sign).expect("non-null function pointer")(
        (*si).session,
        from as *mut CK_BYTE,
        flen as libc::c_ulong,
        to,
        &mut tlen,
    );
    if rv == 0 as libc::c_int as libc::c_ulong {
        rval = tlen as libc::c_int;
    } else {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 27], &[libc::c_char; 27]>(
                b"pkcs11_rsa_private_encrypt\0",
            ))
            .as_ptr(),
            451 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_Sign failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
    }
    return rval;
}
unsafe extern "C" fn pkcs11_rsa_private_decrypt(
    mut _flen: libc::c_int,
    mut _from: *const u_char,
    mut _to: *mut u_char,
    mut _rsa: *mut RSA,
    mut _padding: libc::c_int,
) -> libc::c_int {
    return -(1 as libc::c_int);
}
unsafe extern "C" fn pkcs11_rsa_start_wrapper() -> libc::c_int {
    if !rsa_method.is_null() {
        return 0 as libc::c_int;
    }
    rsa_method = RSA_meth_dup(RSA_get_default_method());
    if rsa_method.is_null() {
        return -(1 as libc::c_int);
    }
    rsa_idx = CRYPTO_get_ex_new_index(
        9 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        b"ssh-pkcs11-rsa\0" as *const u8 as *const libc::c_char as *mut libc::c_void,
        None,
        None,
        Some(
            pkcs11_k11_free
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_void,
                    *mut CRYPTO_EX_DATA,
                    libc::c_int,
                    libc::c_long,
                    *mut libc::c_void,
                ) -> (),
        ),
    );
    if rsa_idx == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    if RSA_meth_set1_name(rsa_method, b"pkcs11\0" as *const u8 as *const libc::c_char) == 0
        || RSA_meth_set_priv_enc(
            rsa_method,
            Some(
                pkcs11_rsa_private_encrypt
                    as unsafe extern "C" fn(
                        libc::c_int,
                        *const u_char,
                        *mut u_char,
                        *mut RSA,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
        ) == 0
        || RSA_meth_set_priv_dec(
            rsa_method,
            Some(
                pkcs11_rsa_private_decrypt
                    as unsafe extern "C" fn(
                        libc::c_int,
                        *const u_char,
                        *mut u_char,
                        *mut RSA,
                        libc::c_int,
                    ) -> libc::c_int,
            ),
        ) == 0
    {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"pkcs11_rsa_start_wrapper\0",
            ))
            .as_ptr(),
            478 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"setup pkcs11 method failed\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkcs11_rsa_wrap(
    mut provider: *mut pkcs11_provider,
    mut slotidx: CK_ULONG,
    mut keyid_attrib: *mut CK_ATTRIBUTE,
    mut rsa: *mut RSA,
) -> libc::c_int {
    let mut k11: *mut pkcs11_key = 0 as *mut pkcs11_key;
    if pkcs11_rsa_start_wrapper() == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    k11 = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<pkcs11_key>() as libc::c_ulong,
    ) as *mut pkcs11_key;
    (*k11).provider = provider;
    (*provider).refcount += 1;
    (*provider).refcount;
    (*k11).slotidx = slotidx;
    (*k11).keyid_len = (*keyid_attrib).ulValueLen as libc::c_int;
    if (*k11).keyid_len > 0 as libc::c_int {
        (*k11).keyid = xmalloc((*k11).keyid_len as size_t) as *mut libc::c_char;
        memcpy(
            (*k11).keyid as *mut libc::c_void,
            (*keyid_attrib).pValue,
            (*k11).keyid_len as libc::c_ulong,
        );
    }
    RSA_set_method(rsa, rsa_method);
    RSA_set_ex_data(rsa, rsa_idx, k11 as *mut libc::c_void);
    return 0 as libc::c_int;
}
unsafe extern "C" fn ecdsa_do_sign(
    mut dgst: *const libc::c_uchar,
    mut dgst_len: libc::c_int,
    mut _inv: *const BIGNUM,
    mut _rp: *const BIGNUM,
    mut ec: *mut EC_KEY,
) -> *mut ECDSA_SIG {
    let mut k11: *mut pkcs11_key = 0 as *mut pkcs11_key;
    let mut si: *mut pkcs11_slotinfo = 0 as *mut pkcs11_slotinfo;
    let mut f: *mut CK_FUNCTION_LIST = 0 as *mut CK_FUNCTION_LIST;
    let mut siglen: CK_ULONG = 0 as libc::c_int as CK_ULONG;
    let mut bnlen: CK_ULONG = 0;
    let mut rv: CK_RV = 0;
    let mut ret: *mut ECDSA_SIG = 0 as *mut ECDSA_SIG;
    let mut sig: *mut u_char = 0 as *mut u_char;
    let mut r: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut s: *mut BIGNUM = 0 as *mut BIGNUM;
    k11 = EC_KEY_get_ex_data(ec, ec_key_idx) as *mut pkcs11_key;
    if k11.is_null() {
        ossl_error(b"EC_KEY_get_ex_data failed for ec\0" as *const u8 as *const libc::c_char);
        return 0 as *mut ECDSA_SIG;
    }
    if pkcs11_get_key(k11, 0x1041 as libc::c_int as CK_MECHANISM_TYPE) == -(1 as libc::c_int) {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ecdsa_do_sign\0"))
                .as_ptr(),
            531 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"pkcs11_get_key failed\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut ECDSA_SIG;
    }
    f = (*(*k11).provider).function_list;
    si =
        &mut *((*(*k11).provider).slotinfo).offset((*k11).slotidx as isize) as *mut pkcs11_slotinfo;
    siglen = ECDSA_size(ec) as CK_ULONG;
    sig = xmalloc(siglen) as *mut u_char;
    rv = ((*f).C_Sign).expect("non-null function pointer")(
        (*si).session,
        dgst as *mut CK_BYTE,
        dgst_len as libc::c_ulong,
        sig,
        &mut siglen,
    );
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ecdsa_do_sign\0"))
                .as_ptr(),
            544 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_Sign failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
    } else if siglen < 64 as libc::c_int as libc::c_ulong
        || siglen > 132 as libc::c_int as libc::c_ulong
        || siglen.wrapping_rem(2 as libc::c_int as libc::c_ulong) != 0
    {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ecdsa_do_sign\0"))
                .as_ptr(),
            548 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"bad signature length: %lu\0" as *const u8 as *const libc::c_char,
            siglen,
        );
    } else {
        bnlen = siglen.wrapping_div(2 as libc::c_int as libc::c_ulong);
        ret = ECDSA_SIG_new();
        if ret.is_null() {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ecdsa_do_sign\0"))
                    .as_ptr(),
                553 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"ECDSA_SIG_new failed\0" as *const u8 as *const libc::c_char,
            );
        } else {
            r = BN_bin2bn(sig, bnlen as libc::c_int, 0 as *mut BIGNUM);
            if r.is_null() || {
                s = BN_bin2bn(
                    sig.offset(bnlen as isize),
                    bnlen as libc::c_int,
                    0 as *mut BIGNUM,
                );
                s.is_null()
            } {
                ossl_error(b"BN_bin2bn failed\0" as *const u8 as *const libc::c_char);
                ECDSA_SIG_free(ret);
                ret = 0 as *mut ECDSA_SIG;
            } else if ECDSA_SIG_set0(ret, r, s) == 0 {
                crate::log::sshlog(
                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 14], &[libc::c_char; 14]>(b"ecdsa_do_sign\0"))
                        .as_ptr(),
                    564 as libc::c_int,
                    1 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"ECDSA_SIG_set0 failed\0" as *const u8 as *const libc::c_char,
                );
                ECDSA_SIG_free(ret);
                ret = 0 as *mut ECDSA_SIG;
            } else {
                s = 0 as *mut BIGNUM;
                r = s;
            }
        }
    }
    BN_free(r);
    BN_free(s);
    libc::free(sig as *mut libc::c_void);
    return ret;
}
unsafe extern "C" fn pkcs11_ecdsa_start_wrapper() -> libc::c_int {
    let mut orig_sign: Option<
        unsafe extern "C" fn(
            libc::c_int,
            *const libc::c_uchar,
            libc::c_int,
            *mut libc::c_uchar,
            *mut libc::c_uint,
            *const BIGNUM,
            *const BIGNUM,
            *mut EC_KEY,
        ) -> libc::c_int,
    > = None;
    if !ec_key_method.is_null() {
        return 0 as libc::c_int;
    }
    ec_key_idx = CRYPTO_get_ex_new_index(
        8 as libc::c_int,
        0 as libc::c_int as libc::c_long,
        b"ssh-pkcs11-ecdsa\0" as *const u8 as *const libc::c_char as *mut libc::c_void,
        None,
        None,
        Some(
            pkcs11_k11_free
                as unsafe extern "C" fn(
                    *mut libc::c_void,
                    *mut libc::c_void,
                    *mut CRYPTO_EX_DATA,
                    libc::c_int,
                    libc::c_long,
                    *mut libc::c_void,
                ) -> (),
        ),
    );
    if ec_key_idx == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    ec_key_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
    if ec_key_method.is_null() {
        return -(1 as libc::c_int);
    }
    EC_KEY_METHOD_get_sign(
        ec_key_method,
        &mut orig_sign,
        0 as *mut Option<
            unsafe extern "C" fn(
                *mut EC_KEY,
                *mut BN_CTX,
                *mut *mut BIGNUM,
                *mut *mut BIGNUM,
            ) -> libc::c_int,
        >,
        0 as *mut Option<
            unsafe extern "C" fn(
                *const libc::c_uchar,
                libc::c_int,
                *const BIGNUM,
                *const BIGNUM,
                *mut EC_KEY,
            ) -> *mut ECDSA_SIG,
        >,
    );
    EC_KEY_METHOD_set_sign(
        ec_key_method,
        orig_sign,
        None,
        Some(
            ecdsa_do_sign
                as unsafe extern "C" fn(
                    *const libc::c_uchar,
                    libc::c_int,
                    *const BIGNUM,
                    *const BIGNUM,
                    *mut EC_KEY,
                ) -> *mut ECDSA_SIG,
        ),
    );
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkcs11_ecdsa_wrap(
    mut provider: *mut pkcs11_provider,
    mut slotidx: CK_ULONG,
    mut keyid_attrib: *mut CK_ATTRIBUTE,
    mut ec: *mut EC_KEY,
) -> libc::c_int {
    let mut k11: *mut pkcs11_key = 0 as *mut pkcs11_key;
    if pkcs11_ecdsa_start_wrapper() == -(1 as libc::c_int) {
        return -(1 as libc::c_int);
    }
    k11 = xcalloc(
        1 as libc::c_int as size_t,
        ::core::mem::size_of::<pkcs11_key>() as libc::c_ulong,
    ) as *mut pkcs11_key;
    (*k11).provider = provider;
    (*provider).refcount += 1;
    (*provider).refcount;
    (*k11).slotidx = slotidx;
    (*k11).keyid_len = (*keyid_attrib).ulValueLen as libc::c_int;
    if (*k11).keyid_len > 0 as libc::c_int {
        (*k11).keyid = xmalloc((*k11).keyid_len as size_t) as *mut libc::c_char;
        memcpy(
            (*k11).keyid as *mut libc::c_void,
            (*keyid_attrib).pValue,
            (*k11).keyid_len as libc::c_ulong,
        );
    }
    EC_KEY_set_method(ec, ec_key_method);
    EC_KEY_set_ex_data(ec, ec_key_idx, k11 as *mut libc::c_void);
    return 0 as libc::c_int;
}
unsafe extern "C" fn rmspace(mut buf: *mut u_char, mut len: size_t) {
    let mut i: size_t = 0;
    if len == 0 {
        return;
    }
    i = len.wrapping_sub(1 as libc::c_int as libc::c_ulong);
    while i > 0 as libc::c_int as libc::c_ulong {
        if !(i == len.wrapping_sub(1 as libc::c_int as libc::c_ulong)
            || *buf.offset(i as isize) as libc::c_int == ' ' as i32)
        {
            break;
        }
        *buf.offset(i as isize) = '\0' as i32 as u_char;
        i = i.wrapping_sub(1);
        i;
    }
}
unsafe extern "C" fn pkcs11_open_session(
    mut p: *mut pkcs11_provider,
    mut slotidx: CK_ULONG,
    mut pin: *mut libc::c_char,
    mut user: CK_ULONG,
) -> libc::c_int {
    let mut si: *mut pkcs11_slotinfo = 0 as *mut pkcs11_slotinfo;
    let mut f: *mut CK_FUNCTION_LIST = 0 as *mut CK_FUNCTION_LIST;
    let mut rv: CK_RV = 0;
    let mut session: CK_SESSION_HANDLE = 0;
    let mut login_required: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    f = (*p).function_list;
    si = &mut *((*p).slotinfo).offset(slotidx as isize) as *mut pkcs11_slotinfo;
    login_required = ((*si).token.flags & ((1 as libc::c_int) << 2 as libc::c_int) as libc::c_ulong)
        as libc::c_int;
    if login_required != 0
        && pkcs11_interactive == 0
        && (pin.is_null() || strlen(pin) == 0 as libc::c_int as libc::c_ulong)
    {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"pkcs11_open_session\0"))
                .as_ptr(),
            662 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"pin required\0" as *const u8 as *const libc::c_char,
        );
        return -(4 as libc::c_int);
    }
    rv = ((*f).C_OpenSession).expect("non-null function pointer")(
        *((*p).slotlist).offset(slotidx as isize),
        ((1 as libc::c_int) << 1 as libc::c_int | (1 as libc::c_int) << 2 as libc::c_int)
            as CK_FLAGS,
        0 as *mut libc::c_void,
        None,
        &mut session,
    );
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"pkcs11_open_session\0"))
                .as_ptr(),
            667 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_OpenSession failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
        return -(1 as libc::c_int);
    }
    if login_required != 0 && !pin.is_null() && strlen(pin) != 0 as libc::c_int as libc::c_ulong {
        rv = ((*f).C_Login).expect("non-null function pointer")(
            session,
            user,
            pin as *mut u_char,
            strlen(pin),
        );
        if rv != 0 as libc::c_int as libc::c_ulong && rv != 0x100 as libc::c_int as libc::c_ulong {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                    b"pkcs11_open_session\0",
                ))
                .as_ptr(),
                673 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"C_Login failed: %lu\0" as *const u8 as *const libc::c_char,
                rv,
            );
            ret = if rv == 0xa4 as libc::c_int as libc::c_ulong {
                -(5 as libc::c_int)
            } else {
                -(2 as libc::c_int)
            };
            rv = ((*f).C_CloseSession).expect("non-null function pointer")(session);
            if rv != 0 as libc::c_int as libc::c_ulong {
                crate::log::sshlog(
                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(
                        b"pkcs11_open_session\0",
                    ))
                    .as_ptr(),
                    678 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"C_CloseSession failed: %lu\0" as *const u8 as *const libc::c_char,
                    rv,
                );
            }
            return ret;
        }
        (*si).logged_in = 1 as libc::c_int;
    }
    (*si).session = session;
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkcs11_key_included(
    mut keysp: *mut *mut *mut sshkey,
    mut nkeys: *mut libc::c_int,
    mut key: *mut sshkey,
) -> libc::c_int {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < *nkeys {
        if sshkey_equal(key, *(*keysp).offset(i as isize)) != 0 {
            return 1 as libc::c_int;
        }
        i += 1;
        i;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn pkcs11_fetch_ecdsa_pubkey(
    mut p: *mut pkcs11_provider,
    mut slotidx: CK_ULONG,
    mut obj: *mut CK_OBJECT_HANDLE,
) -> *mut sshkey {
    let mut key_attr: [CK_ATTRIBUTE; 3] = [CK_ATTRIBUTE {
        type_0: 0,
        pValue: 0 as *mut libc::c_void,
        ulValueLen: 0,
    }; 3];
    let mut session: CK_SESSION_HANDLE = 0;
    let mut f: *mut CK_FUNCTION_LIST = 0 as *mut CK_FUNCTION_LIST;
    let mut rv: CK_RV = 0;
    let mut octet: *mut ASN1_OCTET_STRING = 0 as *mut ASN1_OCTET_STRING;
    let mut ec: *mut EC_KEY = 0 as *mut EC_KEY;
    let mut group: *mut EC_GROUP = 0 as *mut EC_GROUP;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut attrp: *const libc::c_uchar = 0 as *const libc::c_uchar;
    let mut i: libc::c_int = 0;
    let mut nid: libc::c_int = 0;
    memset(
        &mut key_attr as *mut [CK_ATTRIBUTE; 3] as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[CK_ATTRIBUTE; 3]>() as libc::c_ulong,
    );
    key_attr[0 as libc::c_int as usize].type_0 = 0x102 as libc::c_int as CK_ATTRIBUTE_TYPE;
    key_attr[1 as libc::c_int as usize].type_0 = 0x181 as libc::c_int as CK_ATTRIBUTE_TYPE;
    key_attr[2 as libc::c_int as usize].type_0 = 0x180 as libc::c_int as CK_ATTRIBUTE_TYPE;
    session = (*((*p).slotinfo).offset(slotidx as isize)).session;
    f = (*p).function_list;
    rv = ((*f).C_GetAttributeValue).expect("non-null function pointer")(
        session,
        *obj,
        key_attr.as_mut_ptr(),
        3 as libc::c_int as libc::c_ulong,
    );
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"pkcs11_fetch_ecdsa_pubkey\0",
            ))
            .as_ptr(),
            726 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_GetAttributeValue failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
        return 0 as *mut sshkey;
    }
    if key_attr[1 as libc::c_int as usize].ulValueLen == 0 as libc::c_int as libc::c_ulong
        || key_attr[2 as libc::c_int as usize].ulValueLen == 0 as libc::c_int as libc::c_ulong
    {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"pkcs11_fetch_ecdsa_pubkey\0",
            ))
            .as_ptr(),
            737 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"invalid attribute length\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut sshkey;
    }
    i = 0 as libc::c_int;
    while i < 3 as libc::c_int {
        if key_attr[i as usize].ulValueLen > 0 as libc::c_int as libc::c_ulong {
            key_attr[i as usize].pValue =
                xcalloc(1 as libc::c_int as size_t, key_attr[i as usize].ulValueLen);
        }
        i += 1;
        i;
    }
    rv = ((*f).C_GetAttributeValue).expect("non-null function pointer")(
        session,
        *obj,
        key_attr.as_mut_ptr(),
        3 as libc::c_int as libc::c_ulong,
    );
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                b"pkcs11_fetch_ecdsa_pubkey\0",
            ))
            .as_ptr(),
            749 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_GetAttributeValue failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
    } else {
        ec = EC_KEY_new();
        if ec.is_null() {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                    b"pkcs11_fetch_ecdsa_pubkey\0",
                ))
                .as_ptr(),
                755 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"EC_KEY_new failed\0" as *const u8 as *const libc::c_char,
            );
        } else {
            attrp = key_attr[2 as libc::c_int as usize].pValue as *const libc::c_uchar;
            group = d2i_ECPKParameters(
                0 as *mut *mut EC_GROUP,
                &mut attrp,
                key_attr[2 as libc::c_int as usize].ulValueLen as libc::c_long,
            );
            if group.is_null() {
                ossl_error(b"d2i_ECPKParameters failed\0" as *const u8 as *const libc::c_char);
            } else if EC_KEY_set_group(ec, group) == 0 as libc::c_int {
                ossl_error(b"EC_KEY_set_group failed\0" as *const u8 as *const libc::c_char);
            } else if key_attr[1 as libc::c_int as usize].ulValueLen
                <= 2 as libc::c_int as libc::c_ulong
            {
                crate::log::sshlog(
                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                        b"pkcs11_fetch_ecdsa_pubkey\0",
                    ))
                    .as_ptr(),
                    772 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"CKA_EC_POINT too small\0" as *const u8 as *const libc::c_char,
                );
            } else {
                attrp = key_attr[1 as libc::c_int as usize].pValue as *const libc::c_uchar;
                octet = d2i_ASN1_OCTET_STRING(
                    0 as *mut *mut ASN1_OCTET_STRING,
                    &mut attrp,
                    key_attr[1 as libc::c_int as usize].ulValueLen as libc::c_long,
                );
                if octet.is_null() {
                    ossl_error(
                        b"d2i_ASN1_OCTET_STRING failed\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    attrp = (*octet).data;
                    if (o2i_ECPublicKey(&mut ec, &mut attrp, (*octet).length as libc::c_long))
                        .is_null()
                    {
                        ossl_error(b"o2i_ECPublicKey failed\0" as *const u8 as *const libc::c_char);
                    } else {
                        nid = sshkey_ecdsa_key_to_nid(ec);
                        if nid < 0 as libc::c_int {
                            crate::log::sshlog(
                                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                    b"pkcs11_fetch_ecdsa_pubkey\0",
                                ))
                                .as_ptr(),
                                790 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"couldn't get curve nid\0" as *const u8 as *const libc::c_char,
                            );
                        } else if !(pkcs11_ecdsa_wrap(
                            p,
                            slotidx,
                            &mut *key_attr.as_mut_ptr().offset(0 as libc::c_int as isize),
                            ec,
                        ) != 0)
                        {
                            key = sshkey_new(KEY_UNSPEC as libc::c_int);
                            if key.is_null() {
                                crate::log::sshlog(
                                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 26], &[libc::c_char; 26]>(
                                        b"pkcs11_fetch_ecdsa_pubkey\0",
                                    ))
                                    .as_ptr(),
                                    799 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
                                );
                            } else {
                                (*key).ecdsa = ec;
                                (*key).ecdsa_nid = nid;
                                (*key).type_0 = KEY_ECDSA as libc::c_int;
                                (*key).flags |= 0x1 as libc::c_int;
                                ec = 0 as *mut EC_KEY;
                            }
                        }
                    }
                }
            }
        }
    }
    i = 0 as libc::c_int;
    while i < 3 as libc::c_int {
        libc::free(key_attr[i as usize].pValue);
        i += 1;
        i;
    }
    if !ec.is_null() {
        EC_KEY_free(ec);
    }
    if !group.is_null() {
        EC_GROUP_free(group);
    }
    if !octet.is_null() {
        ASN1_OCTET_STRING_free(octet);
    }
    return key;
}
unsafe extern "C" fn pkcs11_fetch_rsa_pubkey(
    mut p: *mut pkcs11_provider,
    mut slotidx: CK_ULONG,
    mut obj: *mut CK_OBJECT_HANDLE,
) -> *mut sshkey {
    let mut key_attr: [CK_ATTRIBUTE; 3] = [CK_ATTRIBUTE {
        type_0: 0,
        pValue: 0 as *mut libc::c_void,
        ulValueLen: 0,
    }; 3];
    let mut session: CK_SESSION_HANDLE = 0;
    let mut f: *mut CK_FUNCTION_LIST = 0 as *mut CK_FUNCTION_LIST;
    let mut rv: CK_RV = 0;
    let mut rsa: *mut RSA = 0 as *mut RSA;
    let mut rsa_n: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut rsa_e: *mut BIGNUM = 0 as *mut BIGNUM;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut i: libc::c_int = 0;
    memset(
        &mut key_attr as *mut [CK_ATTRIBUTE; 3] as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[CK_ATTRIBUTE; 3]>() as libc::c_ulong,
    );
    key_attr[0 as libc::c_int as usize].type_0 = 0x102 as libc::c_int as CK_ATTRIBUTE_TYPE;
    key_attr[1 as libc::c_int as usize].type_0 = 0x120 as libc::c_int as CK_ATTRIBUTE_TYPE;
    key_attr[2 as libc::c_int as usize].type_0 = 0x122 as libc::c_int as CK_ATTRIBUTE_TYPE;
    session = (*((*p).slotinfo).offset(slotidx as isize)).session;
    f = (*p).function_list;
    rv = ((*f).C_GetAttributeValue).expect("non-null function pointer")(
        session,
        *obj,
        key_attr.as_mut_ptr(),
        3 as libc::c_int as libc::c_ulong,
    );
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"pkcs11_fetch_rsa_pubkey\0",
            ))
            .as_ptr(),
            847 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_GetAttributeValue failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
        return 0 as *mut sshkey;
    }
    if key_attr[1 as libc::c_int as usize].ulValueLen == 0 as libc::c_int as libc::c_ulong
        || key_attr[2 as libc::c_int as usize].ulValueLen == 0 as libc::c_int as libc::c_ulong
    {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"pkcs11_fetch_rsa_pubkey\0",
            ))
            .as_ptr(),
            858 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"invalid attribute length\0" as *const u8 as *const libc::c_char,
        );
        return 0 as *mut sshkey;
    }
    i = 0 as libc::c_int;
    while i < 3 as libc::c_int {
        if key_attr[i as usize].ulValueLen > 0 as libc::c_int as libc::c_ulong {
            key_attr[i as usize].pValue =
                xcalloc(1 as libc::c_int as size_t, key_attr[i as usize].ulValueLen);
        }
        i += 1;
        i;
    }
    rv = ((*f).C_GetAttributeValue).expect("non-null function pointer")(
        session,
        *obj,
        key_attr.as_mut_ptr(),
        3 as libc::c_int as libc::c_ulong,
    );
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                b"pkcs11_fetch_rsa_pubkey\0",
            ))
            .as_ptr(),
            870 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_GetAttributeValue failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
    } else {
        rsa = RSA_new();
        if rsa.is_null() {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                    b"pkcs11_fetch_rsa_pubkey\0",
                ))
                .as_ptr(),
                876 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"RSA_new failed\0" as *const u8 as *const libc::c_char,
            );
        } else {
            rsa_n = BN_bin2bn(
                key_attr[1 as libc::c_int as usize].pValue as *const libc::c_uchar,
                key_attr[1 as libc::c_int as usize].ulValueLen as libc::c_int,
                0 as *mut BIGNUM,
            );
            rsa_e = BN_bin2bn(
                key_attr[2 as libc::c_int as usize].pValue as *const libc::c_uchar,
                key_attr[2 as libc::c_int as usize].ulValueLen as libc::c_int,
                0 as *mut BIGNUM,
            );
            if rsa_n.is_null() || rsa_e.is_null() {
                crate::log::sshlog(
                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                        b"pkcs11_fetch_rsa_pubkey\0",
                    ))
                    .as_ptr(),
                    883 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"BN_bin2bn failed\0" as *const u8 as *const libc::c_char,
                );
            } else {
                if RSA_set0_key(rsa, rsa_n, rsa_e, 0 as *mut BIGNUM) == 0 {
                    sshfatal(
                        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                            b"pkcs11_fetch_rsa_pubkey\0",
                        ))
                        .as_ptr(),
                        887 as libc::c_int,
                        1 as libc::c_int,
                        SYSLOG_LEVEL_FATAL,
                        0 as *const libc::c_char,
                        b"set key\0" as *const u8 as *const libc::c_char,
                    );
                }
                rsa_e = 0 as *mut BIGNUM;
                rsa_n = rsa_e;
                if !(pkcs11_rsa_wrap(
                    p,
                    slotidx,
                    &mut *key_attr.as_mut_ptr().offset(0 as libc::c_int as isize),
                    rsa,
                ) != 0)
                {
                    key = sshkey_new(KEY_UNSPEC as libc::c_int);
                    if key.is_null() {
                        crate::log::sshlog(
                            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 24], &[libc::c_char; 24]>(
                                b"pkcs11_fetch_rsa_pubkey\0",
                            ))
                            .as_ptr(),
                            895 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        (*key).rsa = rsa;
                        (*key).type_0 = KEY_RSA as libc::c_int;
                        (*key).flags |= 0x1 as libc::c_int;
                        rsa = 0 as *mut RSA;
                    }
                }
            }
        }
    }
    i = 0 as libc::c_int;
    while i < 3 as libc::c_int {
        libc::free(key_attr[i as usize].pValue);
        i += 1;
        i;
    }
    RSA_free(rsa);
    return key;
}
unsafe extern "C" fn pkcs11_fetch_x509_pubkey(
    mut p: *mut pkcs11_provider,
    mut slotidx: CK_ULONG,
    mut obj: *mut CK_OBJECT_HANDLE,
    mut keyp: *mut *mut sshkey,
    mut labelp: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut cert_attr: [CK_ATTRIBUTE; 3] = [CK_ATTRIBUTE {
        type_0: 0,
        pValue: 0 as *mut libc::c_void,
        ulValueLen: 0,
    }; 3];
    let mut session: CK_SESSION_HANDLE = 0;
    let mut f: *mut CK_FUNCTION_LIST = 0 as *mut CK_FUNCTION_LIST;
    let mut rv: CK_RV = 0;
    let mut x509: *mut X509 = 0 as *mut X509;
    let mut x509_name: *mut X509_NAME = 0 as *mut X509_NAME;
    let mut evp: *mut EVP_PKEY = 0 as *mut EVP_PKEY;
    let mut rsa: *mut RSA = 0 as *mut RSA;
    let mut ec: *mut EC_KEY = 0 as *mut EC_KEY;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut i: libc::c_int = 0;
    let mut nid: libc::c_int = 0;
    let mut cp: *const u_char = 0 as *const u_char;
    let mut subject: *mut libc::c_char = 0 as *mut libc::c_char;
    *keyp = 0 as *mut sshkey;
    *labelp = 0 as *mut libc::c_char;
    memset(
        &mut cert_attr as *mut [CK_ATTRIBUTE; 3] as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[CK_ATTRIBUTE; 3]>() as libc::c_ulong,
    );
    cert_attr[0 as libc::c_int as usize].type_0 = 0x102 as libc::c_int as CK_ATTRIBUTE_TYPE;
    cert_attr[1 as libc::c_int as usize].type_0 = 0x101 as libc::c_int as CK_ATTRIBUTE_TYPE;
    cert_attr[2 as libc::c_int as usize].type_0 = 0x11 as libc::c_int as CK_ATTRIBUTE_TYPE;
    session = (*((*p).slotinfo).offset(slotidx as isize)).session;
    f = (*p).function_list;
    rv = ((*f).C_GetAttributeValue).expect("non-null function pointer")(
        session,
        *obj,
        cert_attr.as_mut_ptr(),
        3 as libc::c_int as libc::c_ulong,
    );
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"pkcs11_fetch_x509_pubkey\0",
            ))
            .as_ptr(),
            949 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_GetAttributeValue failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
        return -(1 as libc::c_int);
    }
    if cert_attr[1 as libc::c_int as usize].ulValueLen == 0 as libc::c_int as libc::c_ulong
        || cert_attr[2 as libc::c_int as usize].ulValueLen == 0 as libc::c_int as libc::c_ulong
    {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"pkcs11_fetch_x509_pubkey\0",
            ))
            .as_ptr(),
            960 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"invalid attribute length\0" as *const u8 as *const libc::c_char,
        );
        return -(1 as libc::c_int);
    }
    i = 0 as libc::c_int;
    while i < 3 as libc::c_int {
        if cert_attr[i as usize].ulValueLen > 0 as libc::c_int as libc::c_ulong {
            cert_attr[i as usize].pValue =
                xcalloc(1 as libc::c_int as size_t, cert_attr[i as usize].ulValueLen);
        }
        i += 1;
        i;
    }
    rv = ((*f).C_GetAttributeValue).expect("non-null function pointer")(
        session,
        *obj,
        cert_attr.as_mut_ptr(),
        3 as libc::c_int as libc::c_ulong,
    );
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"pkcs11_fetch_x509_pubkey\0",
            ))
            .as_ptr(),
            972 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_GetAttributeValue failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
    } else {
        cp = cert_attr[1 as libc::c_int as usize].pValue as *const u_char;
        x509_name = d2i_X509_NAME(
            0 as *mut *mut X509_NAME,
            &mut cp,
            cert_attr[1 as libc::c_int as usize].ulValueLen as libc::c_long,
        );
        if x509_name.is_null() || {
            subject = X509_NAME_oneline(x509_name, 0 as *mut libc::c_char, 0 as libc::c_int);
            subject.is_null()
        } {
            subject =
                crate::xmalloc::xstrdup(b"invalid subject\0" as *const u8 as *const libc::c_char);
        }
        X509_NAME_free(x509_name);
        cp = cert_attr[2 as libc::c_int as usize].pValue as *const u_char;
        x509 = d2i_X509(
            0 as *mut *mut X509,
            &mut cp,
            cert_attr[2 as libc::c_int as usize].ulValueLen as libc::c_long,
        );
        if x509.is_null() {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"pkcs11_fetch_x509_pubkey\0",
                ))
                .as_ptr(),
                986 as libc::c_int,
                0 as libc::c_int,
                SYSLOG_LEVEL_ERROR,
                0 as *const libc::c_char,
                b"d2i_x509 failed\0" as *const u8 as *const libc::c_char,
            );
        } else {
            evp = X509_get_pubkey(x509);
            if evp.is_null() {
                crate::log::sshlog(
                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                        b"pkcs11_fetch_x509_pubkey\0",
                    ))
                    .as_ptr(),
                    991 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"X509_get_pubkey failed\0" as *const u8 as *const libc::c_char,
                );
            } else if EVP_PKEY_get_base_id(evp) == 6 as libc::c_int {
                if (EVP_PKEY_get0_RSA(evp)).is_null() {
                    crate::log::sshlog(
                        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                            b"pkcs11_fetch_x509_pubkey\0",
                        ))
                        .as_ptr(),
                        997 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"invalid x509; no rsa key\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    rsa = RSAPublicKey_dup(EVP_PKEY_get0_RSA(evp));
                    if rsa.is_null() {
                        crate::log::sshlog(
                            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"pkcs11_fetch_x509_pubkey\0",
                            ))
                            .as_ptr(),
                            1001 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"RSAPublicKey_dup failed\0" as *const u8 as *const libc::c_char,
                        );
                    } else if !(pkcs11_rsa_wrap(
                        p,
                        slotidx,
                        &mut *cert_attr.as_mut_ptr().offset(0 as libc::c_int as isize),
                        rsa,
                    ) != 0)
                    {
                        key = sshkey_new(KEY_UNSPEC as libc::c_int);
                        if key.is_null() {
                            crate::log::sshlog(
                                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                    b"pkcs11_fetch_x509_pubkey\0",
                                ))
                                .as_ptr(),
                                1010 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
                            );
                        } else {
                            (*key).rsa = rsa;
                            (*key).type_0 = KEY_RSA as libc::c_int;
                            (*key).flags |= 0x1 as libc::c_int;
                            rsa = 0 as *mut RSA;
                        }
                    }
                }
            } else if EVP_PKEY_get_base_id(evp) == 408 as libc::c_int {
                if (EVP_PKEY_get0_EC_KEY(evp)).is_null() {
                    crate::log::sshlog(
                        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                            b"pkcs11_fetch_x509_pubkey\0",
                        ))
                        .as_ptr(),
                        1021 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"invalid x509; no ec key\0" as *const u8 as *const libc::c_char,
                    );
                } else {
                    ec = EC_KEY_dup(EVP_PKEY_get0_EC_KEY(evp));
                    if ec.is_null() {
                        crate::log::sshlog(
                            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"pkcs11_fetch_x509_pubkey\0",
                            ))
                            .as_ptr(),
                            1025 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"EC_KEY_dup failed\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        nid = sshkey_ecdsa_key_to_nid(ec);
                        if nid < 0 as libc::c_int {
                            crate::log::sshlog(
                                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                    b"pkcs11_fetch_x509_pubkey\0",
                                ))
                                .as_ptr(),
                                1031 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"couldn't get curve nid\0" as *const u8 as *const libc::c_char,
                            );
                        } else if !(pkcs11_ecdsa_wrap(
                            p,
                            slotidx,
                            &mut *cert_attr.as_mut_ptr().offset(0 as libc::c_int as isize),
                            ec,
                        ) != 0)
                        {
                            key = sshkey_new(KEY_UNSPEC as libc::c_int);
                            if key.is_null() {
                                crate::log::sshlog(
                                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                        b"pkcs11_fetch_x509_pubkey\0",
                                    ))
                                    .as_ptr(),
                                    1040 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"sshkey_new failed\0" as *const u8 as *const libc::c_char,
                                );
                            } else {
                                (*key).ecdsa = ec;
                                (*key).ecdsa_nid = nid;
                                (*key).type_0 = KEY_ECDSA as libc::c_int;
                                (*key).flags |= 0x1 as libc::c_int;
                                ec = 0 as *mut EC_KEY;
                            }
                        }
                    }
                }
            } else {
                crate::log::sshlog(
                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                        b"pkcs11_fetch_x509_pubkey\0",
                    ))
                    .as_ptr(),
                    1051 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"unknown certificate key type\0" as *const u8 as *const libc::c_char,
                );
            }
        }
    }
    i = 0 as libc::c_int;
    while i < 3 as libc::c_int {
        libc::free(cert_attr[i as usize].pValue);
        i += 1;
        i;
    }
    X509_free(x509);
    RSA_free(rsa);
    EC_KEY_free(ec);
    if key.is_null() {
        libc::free(subject as *mut libc::c_void);
        return -(1 as libc::c_int);
    }
    *keyp = key;
    *labelp = subject;
    return 0 as libc::c_int;
}
unsafe extern "C" fn note_key(
    mut p: *mut pkcs11_provider,
    mut slotidx: CK_ULONG,
    mut context: *const libc::c_char,
    mut key: *mut sshkey,
) {
    let mut fp: *mut libc::c_char = 0 as *mut libc::c_char;
    fp = sshkey_fingerprint(key, 2 as libc::c_int, SSH_FP_DEFAULT);
    if fp.is_null() {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"note_key\0")).as_ptr(),
            1091 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"sshkey_fingerprint failed\0" as *const u8 as *const libc::c_char,
        );
        return;
    }
    crate::log::sshlog(
        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
        (*::core::mem::transmute::<&[u8; 9], &[libc::c_char; 9]>(b"note_key\0")).as_ptr(),
        1095 as libc::c_int,
        0 as libc::c_int,
        SYSLOG_LEVEL_DEBUG2,
        0 as *const libc::c_char,
        b"%s: provider %s slot %lu: %s %s\0" as *const u8 as *const libc::c_char,
        context,
        (*p).name,
        slotidx,
        sshkey_type(key),
        fp,
    );
    libc::free(fp as *mut libc::c_void);
}
unsafe extern "C" fn pkcs11_fetch_certs(
    mut p: *mut pkcs11_provider,
    mut slotidx: CK_ULONG,
    mut keysp: *mut *mut *mut sshkey,
    mut labelsp: *mut *mut *mut libc::c_char,
    mut nkeys: *mut libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut key_class: CK_OBJECT_CLASS = 0;
    let mut key_attr: [CK_ATTRIBUTE; 1] = [CK_ATTRIBUTE {
        type_0: 0,
        pValue: 0 as *mut libc::c_void,
        ulValueLen: 0,
    }; 1];
    let mut session: CK_SESSION_HANDLE = 0;
    let mut f: *mut CK_FUNCTION_LIST = 0 as *mut CK_FUNCTION_LIST;
    let mut rv: CK_RV = 0;
    let mut obj: CK_OBJECT_HANDLE = 0;
    let mut n: CK_ULONG = 0 as libc::c_int as CK_ULONG;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut label: *mut libc::c_char = 0 as *mut libc::c_char;
    memset(
        &mut key_attr as *mut [CK_ATTRIBUTE; 1] as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[CK_ATTRIBUTE; 1]>() as libc::c_ulong,
    );
    memset(
        &mut obj as *mut CK_OBJECT_HANDLE as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<CK_OBJECT_HANDLE>() as libc::c_ulong,
    );
    key_class = 1 as libc::c_int as CK_OBJECT_CLASS;
    key_attr[0 as libc::c_int as usize].type_0 = 0 as libc::c_int as CK_ATTRIBUTE_TYPE;
    key_attr[0 as libc::c_int as usize].pValue =
        &mut key_class as *mut CK_OBJECT_CLASS as *mut libc::c_void;
    key_attr[0 as libc::c_int as usize].ulValueLen =
        ::core::mem::size_of::<CK_OBJECT_CLASS>() as libc::c_ulong;
    session = (*((*p).slotinfo).offset(slotidx as isize)).session;
    f = (*p).function_list;
    rv = ((*f).C_FindObjectsInit).expect("non-null function pointer")(
        session,
        key_attr.as_mut_ptr(),
        1 as libc::c_int as libc::c_ulong,
    );
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"pkcs11_fetch_certs\0"))
                .as_ptr(),
            1132 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_FindObjectsInit failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
    } else {
        loop {
            let mut ck_cert_type: CK_CERTIFICATE_TYPE = 0;
            rv = ((*f).C_FindObjects).expect("non-null function pointer")(
                session,
                &mut obj,
                1 as libc::c_int as libc::c_ulong,
                &mut n,
            );
            if rv != 0 as libc::c_int as libc::c_ulong {
                crate::log::sshlog(
                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                        b"pkcs11_fetch_certs\0",
                    ))
                    .as_ptr(),
                    1141 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"C_FindObjects failed: %lu\0" as *const u8 as *const libc::c_char,
                    rv,
                );
                current_block = 7167138462392243999;
                break;
            } else {
                if n == 0 as libc::c_int as libc::c_ulong {
                    current_block = 980989089337379490;
                    break;
                }
                memset(
                    &mut ck_cert_type as *mut CK_CERTIFICATE_TYPE as *mut libc::c_void,
                    0 as libc::c_int,
                    ::core::mem::size_of::<CK_CERTIFICATE_TYPE>() as libc::c_ulong,
                );
                memset(
                    &mut key_attr as *mut [CK_ATTRIBUTE; 1] as *mut libc::c_void,
                    0 as libc::c_int,
                    ::core::mem::size_of::<[CK_ATTRIBUTE; 1]>() as libc::c_ulong,
                );
                key_attr[0 as libc::c_int as usize].type_0 =
                    0x80 as libc::c_int as CK_ATTRIBUTE_TYPE;
                key_attr[0 as libc::c_int as usize].pValue =
                    &mut ck_cert_type as *mut CK_CERTIFICATE_TYPE as *mut libc::c_void;
                key_attr[0 as libc::c_int as usize].ulValueLen =
                    ::core::mem::size_of::<CK_CERTIFICATE_TYPE>() as libc::c_ulong;
                rv = ((*f).C_GetAttributeValue).expect("non-null function pointer")(
                    session,
                    obj,
                    key_attr.as_mut_ptr(),
                    1 as libc::c_int as libc::c_ulong,
                );
                if rv != 0 as libc::c_int as libc::c_ulong {
                    crate::log::sshlog(
                        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                            b"pkcs11_fetch_certs\0",
                        ))
                        .as_ptr(),
                        1155 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"C_GetAttributeValue failed: %lu\0" as *const u8 as *const libc::c_char,
                        rv,
                    );
                    current_block = 7167138462392243999;
                    break;
                } else {
                    key = 0 as *mut sshkey;
                    label = 0 as *mut libc::c_char;
                    match ck_cert_type {
                        0 => {
                            if pkcs11_fetch_x509_pubkey(p, slotidx, &mut obj, &mut key, &mut label)
                                != 0 as libc::c_int
                            {
                                crate::log::sshlog(
                                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                        b"pkcs11_fetch_certs\0",
                                    ))
                                    .as_ptr(),
                                    1165 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"failed to fetch key\0" as *const u8 as *const libc::c_char,
                                );
                            } else {
                                note_key(
                                    p,
                                    slotidx,
                                    (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                        b"pkcs11_fetch_certs\0",
                                    ))
                                    .as_ptr(),
                                    key,
                                );
                                if pkcs11_key_included(keysp, nkeys, key) != 0 {
                                    crate::log::sshlog(
                                        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                            b"pkcs11_fetch_certs\0",
                                        ))
                                        .as_ptr(),
                                        1176 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG2,
                                        0 as *const libc::c_char,
                                        b"key already included\0" as *const u8
                                            as *const libc::c_char,
                                    );
                                    sshkey_free(key);
                                } else {
                                    *keysp = xrecallocarray(
                                        *keysp as *mut libc::c_void,
                                        *nkeys as size_t,
                                        (*nkeys + 1 as libc::c_int) as size_t,
                                        ::core::mem::size_of::<*mut sshkey>() as libc::c_ulong,
                                    )
                                        as *mut *mut sshkey;
                                    let ref mut fresh0 = *(*keysp).offset(*nkeys as isize);
                                    *fresh0 = key;
                                    if !labelsp.is_null() {
                                        *labelsp = xrecallocarray(
                                            *labelsp as *mut libc::c_void,
                                            *nkeys as size_t,
                                            (*nkeys + 1 as libc::c_int) as size_t,
                                            ::core::mem::size_of::<*mut libc::c_char>()
                                                as libc::c_ulong,
                                        )
                                            as *mut *mut libc::c_char;
                                        let ref mut fresh1 = *(*labelsp).offset(*nkeys as isize);
                                        *fresh1 = crate::xmalloc::xstrdup(label);
                                    }
                                    *nkeys = *nkeys + 1 as libc::c_int;
                                    crate::log::sshlog(
                                        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                            b"pkcs11_fetch_certs\0",
                                        ))
                                        .as_ptr(),
                                        1189 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG1,
                                        0 as *const libc::c_char,
                                        b"have %d keys\0" as *const u8 as *const libc::c_char,
                                        *nkeys,
                                    );
                                }
                            }
                        }
                        _ => {
                            crate::log::sshlog(
                                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(
                                    b"pkcs11_fetch_certs\0",
                                ))
                                .as_ptr(),
                                1171 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"skipping unsupported certificate type %lu\0" as *const u8
                                    as *const libc::c_char,
                                ck_cert_type,
                            );
                        }
                    }
                }
            }
        }
        match current_block {
            7167138462392243999 => {}
            _ => {
                ret = 0 as libc::c_int;
            }
        }
    }
    rv = ((*f).C_FindObjectsFinal).expect("non-null function pointer")(session);
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 19], &[libc::c_char; 19]>(b"pkcs11_fetch_certs\0"))
                .as_ptr(),
            1197 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_FindObjectsFinal failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
        ret = -(1 as libc::c_int);
    }
    return ret;
}
unsafe extern "C" fn pkcs11_fetch_keys(
    mut p: *mut pkcs11_provider,
    mut slotidx: CK_ULONG,
    mut keysp: *mut *mut *mut sshkey,
    mut labelsp: *mut *mut *mut libc::c_char,
    mut nkeys: *mut libc::c_int,
) -> libc::c_int {
    let mut current_block: u64;
    let mut key: *mut sshkey = 0 as *mut sshkey;
    let mut key_class: CK_OBJECT_CLASS = 0;
    let mut key_attr: [CK_ATTRIBUTE; 2] = [CK_ATTRIBUTE {
        type_0: 0,
        pValue: 0 as *mut libc::c_void,
        ulValueLen: 0,
    }; 2];
    let mut session: CK_SESSION_HANDLE = 0;
    let mut f: *mut CK_FUNCTION_LIST = 0 as *mut CK_FUNCTION_LIST;
    let mut rv: CK_RV = 0;
    let mut obj: CK_OBJECT_HANDLE = 0;
    let mut n: CK_ULONG = 0 as libc::c_int as CK_ULONG;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    memset(
        &mut key_attr as *mut [CK_ATTRIBUTE; 2] as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<[CK_ATTRIBUTE; 2]>() as libc::c_ulong,
    );
    memset(
        &mut obj as *mut CK_OBJECT_HANDLE as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<CK_OBJECT_HANDLE>() as libc::c_ulong,
    );
    key_class = 2 as libc::c_int as CK_OBJECT_CLASS;
    key_attr[0 as libc::c_int as usize].type_0 = 0 as libc::c_int as CK_ATTRIBUTE_TYPE;
    key_attr[0 as libc::c_int as usize].pValue =
        &mut key_class as *mut CK_OBJECT_CLASS as *mut libc::c_void;
    key_attr[0 as libc::c_int as usize].ulValueLen =
        ::core::mem::size_of::<CK_OBJECT_CLASS>() as libc::c_ulong;
    session = (*((*p).slotinfo).offset(slotidx as isize)).session;
    f = (*p).function_list;
    rv = ((*f).C_FindObjectsInit).expect("non-null function pointer")(
        session,
        key_attr.as_mut_ptr(),
        1 as libc::c_int as libc::c_ulong,
    );
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"pkcs11_fetch_keys\0"))
                .as_ptr(),
            1236 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_FindObjectsInit failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
    } else {
        loop {
            let mut ck_key_type: CK_KEY_TYPE = 0;
            let mut label: [CK_UTF8CHAR; 256] = [0; 256];
            rv = ((*f).C_FindObjects).expect("non-null function pointer")(
                session,
                &mut obj,
                1 as libc::c_int as libc::c_ulong,
                &mut n,
            );
            if rv != 0 as libc::c_int as libc::c_ulong {
                crate::log::sshlog(
                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                        b"pkcs11_fetch_keys\0",
                    ))
                    .as_ptr(),
                    1246 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"C_FindObjects failed: %lu\0" as *const u8 as *const libc::c_char,
                    rv,
                );
                current_block = 2369417584951877675;
                break;
            } else {
                if n == 0 as libc::c_int as libc::c_ulong {
                    current_block = 12997042908615822766;
                    break;
                }
                memset(
                    &mut ck_key_type as *mut CK_KEY_TYPE as *mut libc::c_void,
                    0 as libc::c_int,
                    ::core::mem::size_of::<CK_KEY_TYPE>() as libc::c_ulong,
                );
                memset(
                    &mut key_attr as *mut [CK_ATTRIBUTE; 2] as *mut libc::c_void,
                    0 as libc::c_int,
                    ::core::mem::size_of::<[CK_ATTRIBUTE; 2]>() as libc::c_ulong,
                );
                key_attr[0 as libc::c_int as usize].type_0 =
                    0x100 as libc::c_int as CK_ATTRIBUTE_TYPE;
                key_attr[0 as libc::c_int as usize].pValue =
                    &mut ck_key_type as *mut CK_KEY_TYPE as *mut libc::c_void;
                key_attr[0 as libc::c_int as usize].ulValueLen =
                    ::core::mem::size_of::<CK_KEY_TYPE>() as libc::c_ulong;
                key_attr[1 as libc::c_int as usize].type_0 = 3 as libc::c_int as CK_ATTRIBUTE_TYPE;
                key_attr[1 as libc::c_int as usize].pValue =
                    &mut label as *mut [CK_UTF8CHAR; 256] as *mut libc::c_void;
                key_attr[1 as libc::c_int as usize].ulValueLen =
                    (::core::mem::size_of::<[CK_UTF8CHAR; 256]>() as libc::c_ulong)
                        .wrapping_sub(1 as libc::c_int as libc::c_ulong);
                rv = ((*f).C_GetAttributeValue).expect("non-null function pointer")(
                    session,
                    obj,
                    key_attr.as_mut_ptr(),
                    2 as libc::c_int as libc::c_ulong,
                );
                if rv != 0 as libc::c_int as libc::c_ulong {
                    crate::log::sshlog(
                        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                            b"pkcs11_fetch_keys\0",
                        ))
                        .as_ptr(),
                        1263 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"C_GetAttributeValue failed: %lu\0" as *const u8 as *const libc::c_char,
                        rv,
                    );
                    current_block = 2369417584951877675;
                    break;
                } else {
                    label[key_attr[1 as libc::c_int as usize].ulValueLen as usize] =
                        '\0' as i32 as CK_UTF8CHAR;
                    match ck_key_type {
                        0 => {
                            key = pkcs11_fetch_rsa_pubkey(p, slotidx, &mut obj);
                        }
                        3 => {
                            key = pkcs11_fetch_ecdsa_pubkey(p, slotidx, &mut obj);
                        }
                        _ => {
                            key = 0 as *mut sshkey;
                            crate::log::sshlog(
                                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                                    b"pkcs11_fetch_keys\0",
                                ))
                                .as_ptr(),
                                1281 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"skipping unsupported key type\0" as *const u8
                                    as *const libc::c_char,
                            );
                        }
                    }
                    if key.is_null() {
                        crate::log::sshlog(
                            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                                b"pkcs11_fetch_keys\0",
                            ))
                            .as_ptr(),
                            1285 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"failed to fetch key\0" as *const u8 as *const libc::c_char,
                        );
                    } else {
                        note_key(
                            p,
                            slotidx,
                            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                                b"pkcs11_fetch_keys\0",
                            ))
                            .as_ptr(),
                            key,
                        );
                        if pkcs11_key_included(keysp, nkeys, key) != 0 {
                            crate::log::sshlog(
                                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                                    b"pkcs11_fetch_keys\0",
                                ))
                                .as_ptr(),
                                1290 as libc::c_int,
                                1 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG2,
                                0 as *const libc::c_char,
                                b"key already included\0" as *const u8 as *const libc::c_char,
                            );
                            sshkey_free(key);
                        } else {
                            *keysp = xrecallocarray(
                                *keysp as *mut libc::c_void,
                                *nkeys as size_t,
                                (*nkeys + 1 as libc::c_int) as size_t,
                                ::core::mem::size_of::<*mut sshkey>() as libc::c_ulong,
                            ) as *mut *mut sshkey;
                            let ref mut fresh2 = *(*keysp).offset(*nkeys as isize);
                            *fresh2 = key;
                            if !labelsp.is_null() {
                                *labelsp = xrecallocarray(
                                    *labelsp as *mut libc::c_void,
                                    *nkeys as size_t,
                                    (*nkeys + 1 as libc::c_int) as size_t,
                                    ::core::mem::size_of::<*mut libc::c_char>() as libc::c_ulong,
                                )
                                    as *mut *mut libc::c_char;
                                let ref mut fresh3 = *(*labelsp).offset(*nkeys as isize);
                                *fresh3 = crate::xmalloc::xstrdup(
                                    label.as_mut_ptr() as *mut libc::c_char
                                );
                            }
                            *nkeys = *nkeys + 1 as libc::c_int;
                            crate::log::sshlog(
                                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(
                                    b"pkcs11_fetch_keys\0",
                                ))
                                .as_ptr(),
                                1303 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_DEBUG1,
                                0 as *const libc::c_char,
                                b"have %d keys\0" as *const u8 as *const libc::c_char,
                                *nkeys,
                            );
                        }
                    }
                }
            }
        }
        match current_block {
            2369417584951877675 => {}
            _ => {
                ret = 0 as libc::c_int;
            }
        }
    }
    rv = ((*f).C_FindObjectsFinal).expect("non-null function pointer")(session);
    if rv != 0 as libc::c_int as libc::c_ulong {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 18], &[libc::c_char; 18]>(b"pkcs11_fetch_keys\0"))
                .as_ptr(),
            1311 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_FindObjectsFinal failed: %lu\0" as *const u8 as *const libc::c_char,
            rv,
        );
        ret = -(1 as libc::c_int);
    }
    return ret;
}
unsafe extern "C" fn pkcs11_register_provider(
    mut provider_id: *mut libc::c_char,
    mut pin: *mut libc::c_char,
    mut keyp: *mut *mut *mut sshkey,
    mut labelsp: *mut *mut *mut libc::c_char,
    mut providerp: *mut *mut pkcs11_provider,
    mut user: CK_ULONG,
) -> libc::c_int {
    let mut nkeys: libc::c_int = 0;
    let mut need_finalize: libc::c_int = 0 as libc::c_int;
    let mut ret: libc::c_int = -(1 as libc::c_int);
    let mut p: *mut pkcs11_provider = 0 as *mut pkcs11_provider;
    let mut handle: *mut libc::c_void = 0 as *mut libc::c_void;
    let mut getfunctionlist: Option<unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV> =
        None;
    let mut rv: CK_RV = 0;
    let mut f: *mut CK_FUNCTION_LIST = 0 as *mut CK_FUNCTION_LIST;
    let mut token: *mut CK_TOKEN_INFO = 0 as *mut CK_TOKEN_INFO;
    let mut i: CK_ULONG = 0;
    if !providerp.is_null() {
        *providerp = 0 as *mut pkcs11_provider;
        if !keyp.is_null() {
            *keyp = 0 as *mut *mut sshkey;
        }
        if !labelsp.is_null() {
            *labelsp = 0 as *mut *mut libc::c_char;
        }
        if !(pkcs11_provider_lookup(provider_id)).is_null() {
            crate::log::sshlog(
                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                    b"pkcs11_register_provider\0",
                ))
                .as_ptr(),
                1532 as libc::c_int,
                1 as libc::c_int,
                SYSLOG_LEVEL_DEBUG1,
                0 as *const libc::c_char,
                b"provider already registered: %s\0" as *const u8 as *const libc::c_char,
                provider_id,
            );
        } else {
            handle = dlopen(provider_id, 0x2 as libc::c_int);
            if handle.is_null() {
                crate::log::sshlog(
                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                        b"pkcs11_register_provider\0",
                    ))
                    .as_ptr(),
                    1537 as libc::c_int,
                    0 as libc::c_int,
                    SYSLOG_LEVEL_ERROR,
                    0 as *const libc::c_char,
                    b"dlopen %s failed: %s\0" as *const u8 as *const libc::c_char,
                    provider_id,
                    dlerror(),
                );
            } else {
                getfunctionlist = ::core::mem::transmute::<
                    *mut libc::c_void,
                    Option<unsafe extern "C" fn(*mut *mut CK_FUNCTION_LIST) -> CK_RV>,
                >(dlsym(
                    handle,
                    b"C_GetFunctionList\0" as *const u8 as *const libc::c_char,
                ));
                if getfunctionlist.is_none() {
                    crate::log::sshlog(
                        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                            b"pkcs11_register_provider\0",
                        ))
                        .as_ptr(),
                        1541 as libc::c_int,
                        0 as libc::c_int,
                        SYSLOG_LEVEL_ERROR,
                        0 as *const libc::c_char,
                        b"dlsym(C_GetFunctionList) failed: %s\0" as *const u8
                            as *const libc::c_char,
                        dlerror(),
                    );
                } else {
                    p = xcalloc(
                        1 as libc::c_int as size_t,
                        ::core::mem::size_of::<pkcs11_provider>() as libc::c_ulong,
                    ) as *mut pkcs11_provider;
                    (*p).name = crate::xmalloc::xstrdup(provider_id);
                    (*p).handle = handle;
                    rv = (Some(getfunctionlist.expect("non-null function pointer")))
                        .expect("non-null function pointer")(&mut f);
                    if rv != 0 as libc::c_int as libc::c_ulong {
                        crate::log::sshlog(
                            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                b"pkcs11_register_provider\0",
                            ))
                            .as_ptr(),
                            1550 as libc::c_int,
                            0 as libc::c_int,
                            SYSLOG_LEVEL_ERROR,
                            0 as *const libc::c_char,
                            b"C_GetFunctionList for provider %s failed: %lu\0" as *const u8
                                as *const libc::c_char,
                            provider_id,
                            rv,
                        );
                    } else {
                        (*p).function_list = f;
                        rv = ((*f).C_Initialize).expect("non-null function pointer")(
                            0 as *mut libc::c_void,
                        );
                        if rv != 0 as libc::c_int as libc::c_ulong {
                            crate::log::sshlog(
                                b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                    b"pkcs11_register_provider\0",
                                ))
                                .as_ptr(),
                                1556 as libc::c_int,
                                0 as libc::c_int,
                                SYSLOG_LEVEL_ERROR,
                                0 as *const libc::c_char,
                                b"C_Initialize for provider %s failed: %lu\0" as *const u8
                                    as *const libc::c_char,
                                provider_id,
                                rv,
                            );
                        } else {
                            need_finalize = 1 as libc::c_int;
                            rv = ((*f).C_GetInfo).expect("non-null function pointer")(
                                &mut (*p).info,
                            );
                            if rv != 0 as libc::c_int as libc::c_ulong {
                                crate::log::sshlog(
                                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                        b"pkcs11_register_provider\0",
                                    ))
                                    .as_ptr(),
                                    1562 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_ERROR,
                                    0 as *const libc::c_char,
                                    b"C_GetInfo for provider %s failed: %lu\0" as *const u8
                                        as *const libc::c_char,
                                    provider_id,
                                    rv,
                                );
                            } else {
                                rmspace(
                                    ((*p).info.manufacturerID).as_mut_ptr(),
                                    ::core::mem::size_of::<[libc::c_uchar; 32]>() as libc::c_ulong,
                                );
                                rmspace(
                                    ((*p).info.libraryDescription).as_mut_ptr(),
                                    ::core::mem::size_of::<[libc::c_uchar; 32]>() as libc::c_ulong,
                                );
                                crate::log::sshlog(
                                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                    (*::core::mem::transmute::<
                                        &[u8; 25],
                                        &[libc::c_char; 25],
                                    >(b"pkcs11_register_provider\0"))
                                        .as_ptr(),
                                    1575 as libc::c_int,
                                    0 as libc::c_int,
                                    SYSLOG_LEVEL_DEBUG1,
                                    0 as *const libc::c_char,
                                    b"provider %s: manufacturerID <%s> cryptokiVersion %d.%d libraryDescription <%s> libraryVersion %d.%d\0"
                                        as *const u8 as *const libc::c_char,
                                    provider_id,
                                    ((*p).info.manufacturerID).as_mut_ptr(),
                                    (*p).info.cryptokiVersion.major as libc::c_int,
                                    (*p).info.cryptokiVersion.minor as libc::c_int,
                                    ((*p).info.libraryDescription).as_mut_ptr(),
                                    (*p).info.libraryVersion.major as libc::c_int,
                                    (*p).info.libraryVersion.minor as libc::c_int,
                                );
                                rv = ((*f).C_GetSlotList).expect("non-null function pointer")(
                                    1 as libc::c_int as libc::c_uchar,
                                    0 as *mut CK_SLOT_ID,
                                    &mut (*p).nslots,
                                );
                                if rv != 0 as libc::c_int as libc::c_ulong {
                                    crate::log::sshlog(
                                        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                            b"pkcs11_register_provider\0",
                                        ))
                                        .as_ptr(),
                                        1577 as libc::c_int,
                                        0 as libc::c_int,
                                        SYSLOG_LEVEL_ERROR,
                                        0 as *const libc::c_char,
                                        b"C_GetSlotList failed: %lu\0" as *const u8
                                            as *const libc::c_char,
                                        rv,
                                    );
                                } else if (*p).nslots == 0 as libc::c_int as libc::c_ulong {
                                    crate::log::sshlog(
                                        b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                        (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                                            b"pkcs11_register_provider\0",
                                        ))
                                        .as_ptr(),
                                        1581 as libc::c_int,
                                        1 as libc::c_int,
                                        SYSLOG_LEVEL_DEBUG1,
                                        0 as *const libc::c_char,
                                        b"provider %s returned no slots\0" as *const u8
                                            as *const libc::c_char,
                                        provider_id,
                                    );
                                    ret = -(3 as libc::c_int);
                                } else {
                                    (*p).slotlist = xcalloc(
                                        (*p).nslots,
                                        ::core::mem::size_of::<CK_SLOT_ID>() as libc::c_ulong,
                                    )
                                        as *mut CK_SLOT_ID;
                                    rv = ((*f).C_GetSlotList).expect("non-null function pointer")(
                                        1 as libc::c_int as libc::c_uchar,
                                        (*p).slotlist,
                                        &mut (*p).nslots,
                                    );
                                    if rv != 0 as libc::c_int as libc::c_ulong {
                                        crate::log::sshlog(
                                            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                            (*::core::mem::transmute::<
                                                &[u8; 25],
                                                &[libc::c_char; 25],
                                            >(
                                                b"pkcs11_register_provider\0"
                                            ))
                                            .as_ptr(),
                                            1589 as libc::c_int,
                                            0 as libc::c_int,
                                            SYSLOG_LEVEL_ERROR,
                                            0 as *const libc::c_char,
                                            b"C_GetSlotList for provider %s failed: %lu\0"
                                                as *const u8
                                                as *const libc::c_char,
                                            provider_id,
                                            rv,
                                        );
                                    } else {
                                        (*p).slotinfo = xcalloc(
                                            (*p).nslots,
                                            ::core::mem::size_of::<pkcs11_slotinfo>()
                                                as libc::c_ulong,
                                        )
                                            as *mut pkcs11_slotinfo;
                                        (*p).valid = 1 as libc::c_int;
                                        nkeys = 0 as libc::c_int;
                                        i = 0 as libc::c_int as CK_ULONG;
                                        while i < (*p).nslots {
                                            token =
                                                &mut (*((*p).slotinfo).offset(i as isize)).token;
                                            rv = ((*f).C_GetTokenInfo)
                                                .expect("non-null function pointer")(
                                                *((*p).slotlist).offset(i as isize),
                                                token,
                                            );
                                            if rv != 0 as libc::c_int as libc::c_ulong {
                                                crate::log::sshlog(
                                                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                                    (*::core::mem::transmute::<
                                                        &[u8; 25],
                                                        &[libc::c_char; 25],
                                                    >(b"pkcs11_register_provider\0"))
                                                        .as_ptr(),
                                                    1600 as libc::c_int,
                                                    0 as libc::c_int,
                                                    SYSLOG_LEVEL_ERROR,
                                                    0 as *const libc::c_char,
                                                    b"C_GetTokenInfo for provider %s slot %lu failed: %lu\0"
                                                        as *const u8 as *const libc::c_char,
                                                    provider_id,
                                                    i,
                                                    rv,
                                                );
                                            } else if (*token).flags
                                                & ((1 as libc::c_int) << 10 as libc::c_int)
                                                    as libc::c_ulong
                                                == 0 as libc::c_int as libc::c_ulong
                                            {
                                                crate::log::sshlog(
                                                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                                    (*::core::mem::transmute::<
                                                        &[u8; 25],
                                                        &[libc::c_char; 25],
                                                    >(b"pkcs11_register_provider\0"))
                                                        .as_ptr(),
                                                    1605 as libc::c_int,
                                                    1 as libc::c_int,
                                                    SYSLOG_LEVEL_DEBUG2,
                                                    0 as *const libc::c_char,
                                                    b"ignoring uninitialised token in provider %s slot %lu\0"
                                                        as *const u8 as *const libc::c_char,
                                                    provider_id,
                                                    i,
                                                );
                                            } else {
                                                rmspace(
                                                    ((*token).label).as_mut_ptr(),
                                                    ::core::mem::size_of::<[libc::c_uchar; 32]>()
                                                        as libc::c_ulong,
                                                );
                                                rmspace(
                                                    ((*token).manufacturerID).as_mut_ptr(),
                                                    ::core::mem::size_of::<[libc::c_uchar; 32]>()
                                                        as libc::c_ulong,
                                                );
                                                rmspace(
                                                    ((*token).model).as_mut_ptr(),
                                                    ::core::mem::size_of::<[libc::c_uchar; 16]>()
                                                        as libc::c_ulong,
                                                );
                                                rmspace(
                                                    ((*token).serialNumber).as_mut_ptr(),
                                                    ::core::mem::size_of::<[libc::c_uchar; 16]>()
                                                        as libc::c_ulong,
                                                );
                                                crate::log::sshlog(
                                                    b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
                                                    (*::core::mem::transmute::<
                                                        &[u8; 25],
                                                        &[libc::c_char; 25],
                                                    >(b"pkcs11_register_provider\0"))
                                                        .as_ptr(),
                                                    1616 as libc::c_int,
                                                    0 as libc::c_int,
                                                    SYSLOG_LEVEL_DEBUG1,
                                                    0 as *const libc::c_char,
                                                    b"provider %s slot %lu: label <%s> manufacturerID <%s> model <%s> serial <%s> flags 0x%lx\0"
                                                        as *const u8 as *const libc::c_char,
                                                    provider_id,
                                                    i,
                                                    ((*token).label).as_mut_ptr(),
                                                    ((*token).manufacturerID).as_mut_ptr(),
                                                    ((*token).model).as_mut_ptr(),
                                                    ((*token).serialNumber).as_mut_ptr(),
                                                    (*token).flags,
                                                );
                                                ret = pkcs11_open_session(p, i, pin, user);
                                                if !(ret != 0 as libc::c_int || keyp.is_null()) {
                                                    pkcs11_fetch_keys(
                                                        p, i, keyp, labelsp, &mut nkeys,
                                                    );
                                                    pkcs11_fetch_certs(
                                                        p, i, keyp, labelsp, &mut nkeys,
                                                    );
                                                    if nkeys == 0 as libc::c_int
                                                        && (*((*p).slotinfo).offset(i as isize))
                                                            .logged_in
                                                            == 0
                                                        && pkcs11_interactive != 0
                                                    {
                                                        if pkcs11_login_slot(
                                                            p,
                                                            &mut *((*p).slotinfo)
                                                                .offset(i as isize),
                                                            1 as libc::c_int as CK_USER_TYPE,
                                                        ) < 0 as libc::c_int
                                                        {
                                                            crate::log::sshlog(
                                                                b"ssh-pkcs11.c\0" as *const u8
                                                                    as *const libc::c_char,
                                                                (*::core::mem::transmute::<
                                                                    &[u8; 25],
                                                                    &[libc::c_char; 25],
                                                                >(
                                                                    b"pkcs11_register_provider\0"
                                                                ))
                                                                .as_ptr(),
                                                                1634 as libc::c_int,
                                                                0 as libc::c_int,
                                                                SYSLOG_LEVEL_ERROR,
                                                                0 as *const libc::c_char,
                                                                b"login failed\0" as *const u8
                                                                    as *const libc::c_char,
                                                            );
                                                        } else {
                                                            pkcs11_fetch_keys(
                                                                p, i, keyp, labelsp, &mut nkeys,
                                                            );
                                                            pkcs11_fetch_certs(
                                                                p, i, keyp, labelsp, &mut nkeys,
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                            i = i.wrapping_add(1);
                                            i;
                                        }
                                        *providerp = p;
                                        (*p).next.tqe_next = 0 as *mut pkcs11_provider;
                                        (*p).next.tqe_prev = pkcs11_providers.tqh_last;
                                        *pkcs11_providers.tqh_last = p;
                                        pkcs11_providers.tqh_last = &mut (*p).next.tqe_next;
                                        (*p).refcount += 1;
                                        (*p).refcount;
                                        return nkeys;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    if need_finalize != 0 && {
        rv = ((*f).C_Finalize).expect("non-null function pointer")(0 as *mut libc::c_void);
        rv != 0 as libc::c_int as libc::c_ulong
    } {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 25], &[libc::c_char; 25]>(
                b"pkcs11_register_provider\0",
            ))
            .as_ptr(),
            1652 as libc::c_int,
            0 as libc::c_int,
            SYSLOG_LEVEL_ERROR,
            0 as *const libc::c_char,
            b"C_Finalize for provider %s failed: %lu\0" as *const u8 as *const libc::c_char,
            provider_id,
            rv,
        );
    }
    if !p.is_null() {
        libc::free((*p).name as *mut libc::c_void);
        libc::free((*p).slotlist as *mut libc::c_void);
        libc::free((*p).slotinfo as *mut libc::c_void);
        libc::free(p as *mut libc::c_void);
    }
    if !handle.is_null() {
        dlclose(handle);
    }
    if ret > 0 as libc::c_int {
        ret = -(1 as libc::c_int);
    }
    return ret;
}
pub unsafe extern "C" fn pkcs11_add_provider(
    mut provider_id: *mut libc::c_char,
    mut pin: *mut libc::c_char,
    mut keyp: *mut *mut *mut sshkey,
    mut labelsp: *mut *mut *mut libc::c_char,
) -> libc::c_int {
    let mut p: *mut pkcs11_provider = 0 as *mut pkcs11_provider;
    let mut nkeys: libc::c_int = 0;
    nkeys = pkcs11_register_provider(
        provider_id,
        pin,
        keyp,
        labelsp,
        &mut p,
        1 as libc::c_int as CK_ULONG,
    );
    if nkeys <= 0 as libc::c_int && !p.is_null() {
        if !((*p).next.tqe_next).is_null() {
            (*(*p).next.tqe_next).next.tqe_prev = (*p).next.tqe_prev;
        } else {
            pkcs11_providers.tqh_last = (*p).next.tqe_prev;
        }
        *(*p).next.tqe_prev = (*p).next.tqe_next;
        pkcs11_provider_finalize(p);
        pkcs11_provider_unref(p);
    }
    if nkeys == 0 as libc::c_int {
        crate::log::sshlog(
            b"ssh-pkcs11.c\0" as *const u8 as *const libc::c_char,
            (*::core::mem::transmute::<&[u8; 20], &[libc::c_char; 20]>(b"pkcs11_add_provider\0"))
                .as_ptr(),
            1687 as libc::c_int,
            1 as libc::c_int,
            SYSLOG_LEVEL_DEBUG1,
            0 as *const libc::c_char,
            b"provider %s returned no keys\0" as *const u8 as *const libc::c_char,
            provider_id,
        );
    }
    return nkeys;
}
