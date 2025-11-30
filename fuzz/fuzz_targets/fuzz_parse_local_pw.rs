#![no_main]

use libfuzzer_sys::fuzz_target;
use paserk::core::types::PaserkLocalPw;
use paserk::core::version::{K1, K2, K3, K4};

fuzz_target!(|data: &str| {
    // Try parsing as each version - should never panic
    let _ = PaserkLocalPw::<K1>::try_from(data);
    let _ = PaserkLocalPw::<K2>::try_from(data);
    let _ = PaserkLocalPw::<K3>::try_from(data);
    let _ = PaserkLocalPw::<K4>::try_from(data);
});
