#![no_main]

use libfuzzer_sys::fuzz_target;
use paserk::core::types::PaserkSecret;
use paserk::core::version::{K1, K2, K3, K4};

fuzz_target!(|data: &str| {
    // Try parsing as each version - should never panic
    let _ = PaserkSecret::<K1>::try_from(data);
    let _ = PaserkSecret::<K2>::try_from(data);
    let _ = PaserkSecret::<K3>::try_from(data);
    let _ = PaserkSecret::<K4>::try_from(data);
});
