//! Builder patterns for PASERK operations.
//!
//! This module provides fluent builder APIs for password-based key wrapping
//! operations with preset security profiles.
//!
//! # Security Profiles
//!
//! Three preset profiles are available:
//!
//! | Profile | Memory | Iterations | Use Case |
//! |---------|--------|------------|----------|
//! | `interactive()` | 64 MiB | 2 | Fast, interactive logins |
//! | `moderate()` | 256 MiB | 3 | Balanced security (default) |
//! | `sensitive()` | 1 GiB | 4 | High-security, long-term storage |
//!
//! # Example
//!
//! ```rust
//! use paserk::prelude::*;
//!
//! let key = PaserkLocal::<K4>::from([0x42u8; 32]);
//!
//! // Use a preset profile
//! let wrapped = LocalPwBuilder::<K4>::moderate()
//!     .try_wrap(&key, b"password")
//!     .expect("wrap should succeed");
//!
//! // Or customize parameters
//! let wrapped = LocalPwBuilder::<K4>::new()
//!     .memory_kib(128 * 1024)
//!     .iterations(3)
//!     .parallelism(2)
//!     .try_wrap(&key, b"password")
//!     .expect("wrap should succeed");
//! ```

use core::marker::PhantomData;

use crate::core::error::PaserkResult;
use crate::core::types::{PaserkLocal, PaserkLocalPw, PaserkSecret, PaserkSecretPw};
use crate::core::version::PaserkVersion;

#[cfg(any(feature = "k2", feature = "k4"))]
use crate::core::operations::pbkw::Argon2Params;

#[cfg(any(feature = "k2", feature = "k4"))]
use crate::core::version::UsesArgon2;

/// Builder for password-based symmetric key wrapping.
///
/// Provides a fluent API for wrapping `PaserkLocal` keys with a password
/// using configurable Argon2id parameters.
///
/// # Example
///
/// ```rust
/// use paserk::prelude::*;
///
/// let key = PaserkLocal::<K4>::from([0x42u8; 32]);
///
/// // Use a preset profile
/// let wrapped = LocalPwBuilder::<K4>::moderate()
///     .try_wrap(&key, b"password")
///     .expect("wrap should succeed");
///
/// // Customize parameters
/// let wrapped = LocalPwBuilder::<K4>::new()
///     .memory_kib(128 * 1024)
///     .iterations(4)
///     .try_wrap(&key, b"password")
///     .expect("wrap should succeed");
/// ```
#[derive(Debug, Clone, Copy)]
pub struct LocalPwBuilder<V: PaserkVersion> {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    _version: PhantomData<V>,
}

impl<V: PaserkVersion> Default for LocalPwBuilder<V> {
    fn default() -> Self {
        Self::moderate()
    }
}

impl<V: PaserkVersion> LocalPwBuilder<V> {
    /// Creates a new builder with default (moderate) parameters.
    ///
    /// Equivalent to calling `LocalPwBuilder::moderate()`.
    #[must_use]
    pub const fn new() -> Self {
        Self::moderate()
    }

    /// Interactive profile: Fast enough for user logins.
    ///
    /// - Memory: 64 MiB
    /// - Iterations: 2
    /// - Parallelism: 1
    ///
    /// Use this for interactive authentication where responsiveness
    /// is important.
    #[must_use]
    pub const fn interactive() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 2,
            parallelism: 1,
            _version: PhantomData,
        }
    }

    /// Moderate profile: Balanced security and performance.
    ///
    /// - Memory: 256 MiB
    /// - Iterations: 3
    /// - Parallelism: 1
    ///
    /// This is the recommended default for most applications.
    #[must_use]
    pub const fn moderate() -> Self {
        Self {
            memory_kib: 256 * 1024,
            iterations: 3,
            parallelism: 1,
            _version: PhantomData,
        }
    }

    /// Sensitive profile: High security for long-term storage.
    ///
    /// - Memory: 1 GiB
    /// - Iterations: 4
    /// - Parallelism: 1
    ///
    /// Use this for keys that will be stored long-term or
    /// require maximum protection against brute-force attacks.
    #[must_use]
    pub const fn sensitive() -> Self {
        Self {
            memory_kib: 1024 * 1024,
            iterations: 4,
            parallelism: 1,
            _version: PhantomData,
        }
    }

    /// Sets the memory cost in KiB.
    ///
    /// Higher values increase resistance to GPU-based attacks
    /// but require more RAM during key derivation.
    ///
    /// # Arguments
    ///
    /// * `memory_kib` - Memory cost in kibibytes (1024 bytes each)
    #[must_use]
    pub const fn memory_kib(mut self, memory_kib: u32) -> Self {
        self.memory_kib = memory_kib;
        self
    }

    /// Sets the number of iterations (time cost).
    ///
    /// Higher values increase the time required for key derivation,
    /// making brute-force attacks slower.
    ///
    /// # Arguments
    ///
    /// * `iterations` - Number of iterations
    #[must_use]
    pub const fn iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    /// Sets the degree of parallelism.
    ///
    /// This controls how many parallel threads can be used
    /// during key derivation. Higher values can speed up
    /// derivation on multi-core systems.
    ///
    /// # Arguments
    ///
    /// * `parallelism` - Number of parallel threads
    #[must_use]
    pub const fn parallelism(mut self, parallelism: u32) -> Self {
        self.parallelism = parallelism;
        self
    }

    /// Returns the configured memory cost in KiB.
    #[must_use]
    pub const fn get_memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Returns the configured number of iterations.
    #[must_use]
    pub const fn get_iterations(&self) -> u32 {
        self.iterations
    }

    /// Returns the configured parallelism.
    #[must_use]
    pub const fn get_parallelism(&self) -> u32 {
        self.parallelism
    }
}

#[cfg(any(feature = "k2", feature = "k4"))]
impl<V: PaserkVersion + UsesArgon2> LocalPwBuilder<V> {
    /// Wraps the key with the given password.
    ///
    /// # Arguments
    ///
    /// * `key` - The symmetric key to wrap
    /// * `password` - The password to use for wrapping
    ///
    /// # Returns
    ///
    /// A new `PaserkLocalPw` containing the wrapped key.
    ///
    /// # Errors
    ///
    /// Returns an error if the cryptographic operation fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use paserk::prelude::*;
    ///
    /// let key = PaserkLocal::<K4>::from([0x42u8; 32]);
    /// let wrapped = LocalPwBuilder::<K4>::moderate()
    ///     .try_wrap(&key, b"password")
    ///     .expect("wrap should succeed");
    /// ```
    pub fn try_wrap(self, key: &PaserkLocal<V>, password: &[u8]) -> PaserkResult<PaserkLocalPw<V>> {
        let params = Argon2Params {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        };
        PaserkLocalPw::try_wrap(key, password, params)
    }

    /// Converts this builder's parameters to `Argon2Params`.
    ///
    /// Useful when you need to pass parameters to the underlying
    /// PBKW functions directly.
    #[must_use]
    pub const fn to_params(&self) -> Argon2Params {
        Argon2Params {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        }
    }
}

/// Builder for password-based secret key wrapping.
///
/// Provides a fluent API for wrapping `PaserkSecret` keys with a password
/// using configurable Argon2id parameters.
///
/// # Example
///
/// ```rust
/// use paserk::prelude::*;
///
/// let key = PaserkSecret::<K4>::from([0x42u8; 64]);
///
/// // Use a preset profile
/// let wrapped = SecretPwBuilder::<K4>::moderate()
///     .try_wrap(&key, b"password")
///     .expect("wrap should succeed");
///
/// // Customize parameters
/// let wrapped = SecretPwBuilder::<K4>::new()
///     .memory_kib(128 * 1024)
///     .iterations(4)
///     .try_wrap(&key, b"password")
///     .expect("wrap should succeed");
/// ```
#[derive(Debug, Clone, Copy)]
pub struct SecretPwBuilder<V: PaserkVersion> {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    _version: PhantomData<V>,
}

impl<V: PaserkVersion> Default for SecretPwBuilder<V> {
    fn default() -> Self {
        Self::moderate()
    }
}

impl<V: PaserkVersion> SecretPwBuilder<V> {
    /// Creates a new builder with default (moderate) parameters.
    ///
    /// Equivalent to calling `SecretPwBuilder::moderate()`.
    #[must_use]
    pub const fn new() -> Self {
        Self::moderate()
    }

    /// Interactive profile: Fast enough for user logins.
    ///
    /// - Memory: 64 MiB
    /// - Iterations: 2
    /// - Parallelism: 1
    ///
    /// Use this for interactive authentication where responsiveness
    /// is important.
    #[must_use]
    pub const fn interactive() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 2,
            parallelism: 1,
            _version: PhantomData,
        }
    }

    /// Moderate profile: Balanced security and performance.
    ///
    /// - Memory: 256 MiB
    /// - Iterations: 3
    /// - Parallelism: 1
    ///
    /// This is the recommended default for most applications.
    #[must_use]
    pub const fn moderate() -> Self {
        Self {
            memory_kib: 256 * 1024,
            iterations: 3,
            parallelism: 1,
            _version: PhantomData,
        }
    }

    /// Sensitive profile: High security for long-term storage.
    ///
    /// - Memory: 1 GiB
    /// - Iterations: 4
    /// - Parallelism: 1
    ///
    /// Use this for keys that will be stored long-term or
    /// require maximum protection against brute-force attacks.
    #[must_use]
    pub const fn sensitive() -> Self {
        Self {
            memory_kib: 1024 * 1024,
            iterations: 4,
            parallelism: 1,
            _version: PhantomData,
        }
    }

    /// Sets the memory cost in KiB.
    ///
    /// Higher values increase resistance to GPU-based attacks
    /// but require more RAM during key derivation.
    ///
    /// # Arguments
    ///
    /// * `memory_kib` - Memory cost in kibibytes (1024 bytes each)
    #[must_use]
    pub const fn memory_kib(mut self, memory_kib: u32) -> Self {
        self.memory_kib = memory_kib;
        self
    }

    /// Sets the number of iterations (time cost).
    ///
    /// Higher values increase the time required for key derivation,
    /// making brute-force attacks slower.
    ///
    /// # Arguments
    ///
    /// * `iterations` - Number of iterations
    #[must_use]
    pub const fn iterations(mut self, iterations: u32) -> Self {
        self.iterations = iterations;
        self
    }

    /// Sets the degree of parallelism.
    ///
    /// This controls how many parallel threads can be used
    /// during key derivation. Higher values can speed up
    /// derivation on multi-core systems.
    ///
    /// # Arguments
    ///
    /// * `parallelism` - Number of parallel threads
    #[must_use]
    pub const fn parallelism(mut self, parallelism: u32) -> Self {
        self.parallelism = parallelism;
        self
    }

    /// Returns the configured memory cost in KiB.
    #[must_use]
    pub const fn get_memory_kib(&self) -> u32 {
        self.memory_kib
    }

    /// Returns the configured number of iterations.
    #[must_use]
    pub const fn get_iterations(&self) -> u32 {
        self.iterations
    }

    /// Returns the configured parallelism.
    #[must_use]
    pub const fn get_parallelism(&self) -> u32 {
        self.parallelism
    }
}

#[cfg(any(feature = "k2", feature = "k4"))]
impl<V: PaserkVersion + UsesArgon2> SecretPwBuilder<V> {
    /// Wraps the key with the given password.
    ///
    /// # Arguments
    ///
    /// * `key` - The secret key to wrap
    /// * `password` - The password to use for wrapping
    ///
    /// # Returns
    ///
    /// A new `PaserkSecretPw` containing the wrapped key.
    ///
    /// # Errors
    ///
    /// Returns an error if the cryptographic operation fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use paserk::prelude::*;
    ///
    /// let key = PaserkSecret::<K4>::from([0x42u8; 64]);
    /// let wrapped = SecretPwBuilder::<K4>::moderate()
    ///     .try_wrap(&key, b"password")
    ///     .expect("wrap should succeed");
    /// ```
    pub fn try_wrap(
        self,
        key: &PaserkSecret<V>,
        password: &[u8],
    ) -> PaserkResult<PaserkSecretPw<V>> {
        let params = Argon2Params {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        };
        PaserkSecretPw::try_wrap(key, password, params)
    }

    /// Converts this builder's parameters to `Argon2Params`.
    ///
    /// Useful when you need to pass parameters to the underlying
    /// PBKW functions directly.
    #[must_use]
    pub const fn to_params(&self) -> Argon2Params {
        Argon2Params {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::version::K4;

    #[test]
    fn test_local_pw_builder_profiles() {
        let interactive = LocalPwBuilder::<K4>::interactive();
        assert_eq!(interactive.get_memory_kib(), 64 * 1024);
        assert_eq!(interactive.get_iterations(), 2);
        assert_eq!(interactive.get_parallelism(), 1);

        let moderate = LocalPwBuilder::<K4>::moderate();
        assert_eq!(moderate.get_memory_kib(), 256 * 1024);
        assert_eq!(moderate.get_iterations(), 3);
        assert_eq!(moderate.get_parallelism(), 1);

        let sensitive = LocalPwBuilder::<K4>::sensitive();
        assert_eq!(sensitive.get_memory_kib(), 1024 * 1024);
        assert_eq!(sensitive.get_iterations(), 4);
        assert_eq!(sensitive.get_parallelism(), 1);
    }

    #[test]
    fn test_local_pw_builder_custom() {
        let builder = LocalPwBuilder::<K4>::new()
            .memory_kib(128 * 1024)
            .iterations(5)
            .parallelism(2);

        assert_eq!(builder.get_memory_kib(), 128 * 1024);
        assert_eq!(builder.get_iterations(), 5);
        assert_eq!(builder.get_parallelism(), 2);
    }

    #[test]
    fn test_local_pw_builder_default() {
        let default = LocalPwBuilder::<K4>::default();
        let moderate = LocalPwBuilder::<K4>::moderate();

        assert_eq!(default.get_memory_kib(), moderate.get_memory_kib());
        assert_eq!(default.get_iterations(), moderate.get_iterations());
        assert_eq!(default.get_parallelism(), moderate.get_parallelism());
    }

    #[test]
    fn test_secret_pw_builder_profiles() {
        let interactive = SecretPwBuilder::<K4>::interactive();
        assert_eq!(interactive.get_memory_kib(), 64 * 1024);
        assert_eq!(interactive.get_iterations(), 2);
        assert_eq!(interactive.get_parallelism(), 1);

        let moderate = SecretPwBuilder::<K4>::moderate();
        assert_eq!(moderate.get_memory_kib(), 256 * 1024);
        assert_eq!(moderate.get_iterations(), 3);
        assert_eq!(moderate.get_parallelism(), 1);

        let sensitive = SecretPwBuilder::<K4>::sensitive();
        assert_eq!(sensitive.get_memory_kib(), 1024 * 1024);
        assert_eq!(sensitive.get_iterations(), 4);
        assert_eq!(sensitive.get_parallelism(), 1);
    }

    #[test]
    fn test_secret_pw_builder_custom() {
        let builder = SecretPwBuilder::<K4>::new()
            .memory_kib(128 * 1024)
            .iterations(5)
            .parallelism(2);

        assert_eq!(builder.get_memory_kib(), 128 * 1024);
        assert_eq!(builder.get_iterations(), 5);
        assert_eq!(builder.get_parallelism(), 2);
    }

    #[test]
    fn test_secret_pw_builder_default() {
        let default = SecretPwBuilder::<K4>::default();
        let moderate = SecretPwBuilder::<K4>::moderate();

        assert_eq!(default.get_memory_kib(), moderate.get_memory_kib());
        assert_eq!(default.get_iterations(), moderate.get_iterations());
        assert_eq!(default.get_parallelism(), moderate.get_parallelism());
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_local_pw_builder_to_params() {
        let builder = LocalPwBuilder::<K4>::new()
            .memory_kib(1024)
            .iterations(1)
            .parallelism(1);

        let params = builder.to_params();
        assert_eq!(params.memory_kib, 1024);
        assert_eq!(params.iterations, 1);
        assert_eq!(params.parallelism, 1);
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_secret_pw_builder_to_params() {
        let builder = SecretPwBuilder::<K4>::new()
            .memory_kib(1024)
            .iterations(1)
            .parallelism(1);

        let params = builder.to_params();
        assert_eq!(params.memory_kib, 1024);
        assert_eq!(params.iterations, 1);
        assert_eq!(params.parallelism, 1);
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_local_pw_builder_wrap() -> PaserkResult<()> {
        let key = PaserkLocal::<K4>::from([0x42u8; 32]);
        let password = b"test-password";

        // Use minimal params for fast testing
        let wrapped = LocalPwBuilder::<K4>::new()
            .memory_kib(1024)
            .iterations(1)
            .parallelism(1)
            .try_wrap(&key, password)?;

        // Verify by unwrapping
        let params = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let unwrapped = wrapped.try_unwrap(password, params)?;

        assert_eq!(unwrapped.as_bytes(), key.as_bytes());
        Ok(())
    }

    #[test]
    #[cfg(feature = "k4")]
    fn test_secret_pw_builder_wrap() -> PaserkResult<()> {
        let key = PaserkSecret::<K4>::from([0x42u8; 64]);
        let password = b"test-password";

        // Use minimal params for fast testing
        let wrapped = SecretPwBuilder::<K4>::new()
            .memory_kib(1024)
            .iterations(1)
            .parallelism(1)
            .try_wrap(&key, password)?;

        // Verify by unwrapping
        let params = Argon2Params {
            memory_kib: 1024,
            iterations: 1,
            parallelism: 1,
        };
        let unwrapped = wrapped.try_unwrap(password, params)?;

        assert_eq!(unwrapped.as_bytes(), key.as_bytes());
        Ok(())
    }
}
