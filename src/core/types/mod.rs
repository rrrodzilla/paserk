//! PASERK type implementations.
//!
//! This module provides the core PASERK types for key serialization:
//!
//! - [`PaserkLocal`] - Symmetric key (`k{v}.local.{data}`)
//! - [`PaserkPublic`] - Public key (`k{v}.public.{data}`)
//! - [`PaserkSecret`] - Secret key (`k{v}.secret.{data}`)
//! - [`PaserkLocalId`] - Local key identifier (`k{v}.lid.{data}`)
//! - [`PaserkPublicId`] - Public key identifier (`k{v}.pid.{data}`)
//! - [`PaserkSecretId`] - Secret key identifier (`k{v}.sid.{data}`)
//! - [`PaserkLocalWrap`] - Wrapped symmetric key (`k{v}.local-wrap.{protocol}.{data}`)
//! - [`PaserkSecretWrap`] - Wrapped secret key (`k{v}.secret-wrap.{protocol}.{data}`)
//! - [`PaserkLocalPw`] - Password-wrapped symmetric key (`k{v}.local-pw.{data}`)
//! - [`PaserkSecretPw`] - Password-wrapped secret key (`k{v}.secret-pw.{data}`)
//! - [`PaserkSeal`] - Symmetric key encrypted with public key (`k{v}.seal.{data}`)

mod local;
mod local_id;
mod local_pw;
mod local_wrap;
mod public;
mod public_id;
mod seal;
mod secret;
mod secret_id;
mod secret_pw;
mod secret_wrap;

pub use local::PaserkLocal;
pub use local_id::PaserkLocalId;
pub use local_pw::PaserkLocalPw;
pub use local_wrap::PaserkLocalWrap;
pub use public::PaserkPublic;
pub use public_id::PaserkPublicId;
pub use seal::PaserkSeal;
pub use secret::PaserkSecret;
pub use secret_id::PaserkSecretId;
pub use secret_pw::PaserkSecretPw;
pub use secret_wrap::PaserkSecretWrap;
