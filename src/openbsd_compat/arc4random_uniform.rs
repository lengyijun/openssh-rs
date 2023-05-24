use ::libc;
extern "C" {
    fn arc4random() -> uint32_t;
}
pub type __uint32_t = libc::c_uint;
pub type uint32_t = __uint32_t;
#[no_mangle]
pub unsafe extern "C" fn arc4random_uniform(mut upper_bound: uint32_t) -> uint32_t {
    let mut r: uint32_t = 0;
    let mut min: uint32_t = 0;
    if upper_bound < 2 as libc::c_int as libc::c_uint {
        return 0 as libc::c_int as uint32_t;
    }
    min = upper_bound.wrapping_neg().wrapping_rem(upper_bound);
    loop {
        r = arc4random();
        if r >= min {
            break;
        }
    }
    return r.wrapping_rem(upper_bound);
}
