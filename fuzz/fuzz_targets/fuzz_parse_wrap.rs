#![no_main]

use libfuzzer_sys::fuzz_target;
use paserk::core::operations::wrap::Pie;
use paserk::core::types::{PaserkLocalWrap, PaserkSecretWrap};
use paserk::core::version::{K1, K2, K3, K4};

fuzz_target!(|data: &str| {
    // Try parsing local wrap (PIE protocol) as each version - should never panic
    let _ = PaserkLocalWrap::<K1, Pie>::try_from(data);
    let _ = PaserkLocalWrap::<K2, Pie>::try_from(data);
    let _ = PaserkLocalWrap::<K3, Pie>::try_from(data);
    let _ = PaserkLocalWrap::<K4, Pie>::try_from(data);

    // Try parsing secret wrap (PIE protocol) as each version - should never panic
    let _ = PaserkSecretWrap::<K1, Pie>::try_from(data);
    let _ = PaserkSecretWrap::<K2, Pie>::try_from(data);
    let _ = PaserkSecretWrap::<K3, Pie>::try_from(data);
    let _ = PaserkSecretWrap::<K4, Pie>::try_from(data);
});
