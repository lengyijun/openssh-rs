use ::libc;
extern "C" {}
pub unsafe extern "C" fn ssh_err(mut n: libc::c_int) -> *const libc::c_char {
    match n {
        0 => return b"success\0" as *const u8 as *const libc::c_char,
        -1 => return b"unexpected internal error\0" as *const u8 as *const libc::c_char,
        -2 => return b"memory allocation failed\0" as *const u8 as *const libc::c_char,
        -3 => return b"incomplete message\0" as *const u8 as *const libc::c_char,
        -4 => return b"invalid format\0" as *const u8 as *const libc::c_char,
        -5 => return b"bignum is negative\0" as *const u8 as *const libc::c_char,
        -6 => return b"string is too large\0" as *const u8 as *const libc::c_char,
        -7 => return b"bignum is too large\0" as *const u8 as *const libc::c_char,
        -8 => {
            return b"elliptic curve point is too large\0" as *const u8 as *const libc::c_char;
        }
        -9 => return b"insufficient buffer space\0" as *const u8 as *const libc::c_char,
        -10 => return b"invalid argument\0" as *const u8 as *const libc::c_char,
        -11 => return b"key bits do not match\0" as *const u8 as *const libc::c_char,
        -12 => return b"invalid elliptic curve\0" as *const u8 as *const libc::c_char,
        -13 => return b"key type does not match\0" as *const u8 as *const libc::c_char,
        -14 => {
            return b"unknown or unsupported key type\0" as *const u8 as *const libc::c_char;
        }
        -15 => {
            return b"elliptic curve does not match\0" as *const u8 as *const libc::c_char;
        }
        -16 => {
            return b"plain key provided where certificate required\0" as *const u8
                as *const libc::c_char;
        }
        -17 => return b"key lacks certificate data\0" as *const u8 as *const libc::c_char,
        -18 => {
            return b"unknown/unsupported certificate type\0" as *const u8 as *const libc::c_char;
        }
        -19 => {
            return b"invalid certificate signing key\0" as *const u8 as *const libc::c_char;
        }
        -20 => {
            return b"invalid elliptic curve value\0" as *const u8 as *const libc::c_char;
        }
        -21 => return b"incorrect signature\0" as *const u8 as *const libc::c_char,
        -22 => return b"error in libcrypto\0" as *const u8 as *const libc::c_char,
        -23 => {
            return b"unexpected bytes remain after decoding\0" as *const u8 as *const libc::c_char;
        }
        -24 => return libc::strerror(*libc::__errno_location()),
        -25 => return b"invalid certificate\0" as *const u8 as *const libc::c_char,
        -26 => {
            return b"communication with agent failed\0" as *const u8 as *const libc::c_char;
        }
        -27 => return b"agent refused operation\0" as *const u8 as *const libc::c_char,
        -28 => return b"DH GEX group out of range\0" as *const u8 as *const libc::c_char,
        -29 => return b"disconnected\0" as *const u8 as *const libc::c_char,
        -30 => {
            return b"message authentication code incorrect\0" as *const u8 as *const libc::c_char;
        }
        -31 => return b"no matching cipher found\0" as *const u8 as *const libc::c_char,
        -32 => return b"no matching MAC found\0" as *const u8 as *const libc::c_char,
        -33 => {
            return b"no matching compression method found\0" as *const u8 as *const libc::c_char;
        }
        -34 => {
            return b"no matching key exchange method found\0" as *const u8 as *const libc::c_char;
        }
        -35 => {
            return b"no matching host key type found\0" as *const u8 as *const libc::c_char;
        }
        -37 => return b"protocol version mismatch\0" as *const u8 as *const libc::c_char,
        -38 => {
            return b"could not read protocol version\0" as *const u8 as *const libc::c_char;
        }
        -36 => return b"could not load host key\0" as *const u8 as *const libc::c_char,
        -39 => {
            return b"rekeying not supported by peer\0" as *const u8 as *const libc::c_char;
        }
        -40 => {
            return b"passphrase is too short (minimum five characters)\0" as *const u8
                as *const libc::c_char;
        }
        -41 => return b"file changed while reading\0" as *const u8 as *const libc::c_char,
        -42 => {
            return b"key encrypted using unsupported cipher\0" as *const u8 as *const libc::c_char;
        }
        -43 => {
            return b"incorrect passphrase supplied to decrypt private key\0" as *const u8
                as *const libc::c_char;
        }
        -44 => return b"bad permissions\0" as *const u8 as *const libc::c_char,
        -45 => {
            return b"certificate does not match key\0" as *const u8 as *const libc::c_char;
        }
        -46 => return b"key not found\0" as *const u8 as *const libc::c_char,
        -47 => return b"agent not present\0" as *const u8 as *const libc::c_char,
        -48 => {
            return b"agent contains no identities\0" as *const u8 as *const libc::c_char;
        }
        -49 => {
            return b"internal error: buffer is read-only\0" as *const u8 as *const libc::c_char;
        }
        -50 => {
            return b"KRL file has invalid magic number\0" as *const u8 as *const libc::c_char;
        }
        -51 => return b"Key is revoked\0" as *const u8 as *const libc::c_char,
        -52 => return b"Connection closed\0" as *const u8 as *const libc::c_char,
        -53 => return b"Connection timed out\0" as *const u8 as *const libc::c_char,
        -54 => return b"Connection corrupted\0" as *const u8 as *const libc::c_char,
        -55 => return b"Protocol error\0" as *const u8 as *const libc::c_char,
        -56 => return b"Invalid key length\0" as *const u8 as *const libc::c_char,
        -57 => return b"number is too large\0" as *const u8 as *const libc::c_char,
        -58 => {
            return b"signature algorithm not supported\0" as *const u8 as *const libc::c_char;
        }
        -59 => {
            return b"requested feature not supported\0" as *const u8 as *const libc::c_char;
        }
        -60 => return b"device not found\0" as *const u8 as *const libc::c_char,
        _ => return b"unknown error\0" as *const u8 as *const libc::c_char,
    };
}
