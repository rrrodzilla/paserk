#![no_main]

use libfuzzer_sys::fuzz_target;
use paserk::core::types::PaserkLocal;
use paserk::core::version::{K1, K2, K3, K4};

fuzz_target!(|data: &str| {
    // Try parsing as each version - should never panic
    let _ = PaserkLocal::<K1>::try_from(data);
    let _ = PaserkLocal::<K2>::try_from(data);
    let _ = PaserkLocal::<K3>::try_from(data);
    let _ = PaserkLocal::<K4>::try_from(data);
});
