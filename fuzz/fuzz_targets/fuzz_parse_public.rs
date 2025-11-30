#![no_main]

use libfuzzer_sys::fuzz_target;
use paserk::core::types::PaserkPublic;
use paserk::core::version::{K1, K2, K3, K4};

fuzz_target!(|data: &str| {
    // Try parsing as each version - should never panic
    let _ = PaserkPublic::<K1>::try_from(data);
    let _ = PaserkPublic::<K2>::try_from(data);
    let _ = PaserkPublic::<K3>::try_from(data);
    let _ = PaserkPublic::<K4>::try_from(data);
});
