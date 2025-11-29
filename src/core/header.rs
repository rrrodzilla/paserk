//! Header parsing and generation utilities for PASERK strings.
//!
//! PASERK strings follow the format: `k{version}.{type}.{data}`
//! where version is 1-4 and type is one of the PASERK type identifiers.

use crate::core::error::PaserkError;

/// Parses a PASERK header and returns the version prefix and type.
///
/// # Arguments
///
/// * `paserk` - The full PASERK string
///
/// # Returns
///
/// A tuple of (version_prefix, type_name, data) if successful.
///
/// # Errors
///
/// Returns `PaserkError::InvalidFormat` if the string doesn't have the expected format.
/// Returns `PaserkError::InvalidHeader` if the header is malformed.
pub fn parse_header(paserk: &str) -> Result<(&str, &str, &str), PaserkError> {
    let parts: Vec<&str> = paserk.splitn(3, '.').collect();

    if parts.len() < 3 {
        return Err(PaserkError::InvalidFormat);
    }

    let version = parts[0];
    let type_name = parts[1];
    let data = parts[2];

    // Validate version prefix
    if !matches!(version, "k1" | "k2" | "k3" | "k4") {
        return Err(PaserkError::InvalidVersion);
    }

    // Type must not be empty
    if type_name.is_empty() {
        return Err(PaserkError::InvalidHeader);
    }

    Ok((version, type_name, data))
}

/// Validates that a PASERK string has the expected header.
///
/// # Arguments
///
/// * `paserk` - The full PASERK string
/// * `expected_version` - The expected version prefix (e.g., "k4")
/// * `expected_type` - The expected type name (e.g., "local")
///
/// # Returns
///
/// The data portion of the PASERK string if validation succeeds.
///
/// # Errors
///
/// Returns an appropriate error if validation fails.
pub fn validate_header<'a>(
    paserk: &'a str,
    expected_version: &str,
    expected_type: &str,
) -> Result<&'a str, PaserkError> {
    let (version, type_name, data) = parse_header(paserk)?;

    if version != expected_version {
        return Err(PaserkError::InvalidVersion);
    }

    if type_name != expected_type {
        return Err(PaserkError::InvalidHeader);
    }

    Ok(data)
}

/// Constructs a PASERK header string.
///
/// # Arguments
///
/// * `version` - The version prefix (e.g., "k4")
/// * `type_name` - The type name (e.g., "local")
///
/// # Returns
///
/// The header string with trailing dot (e.g., "k4.local.")
#[must_use]
pub fn make_header(version: &str, type_name: &str) -> String {
    format!("{version}.{type_name}.")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_header_valid() -> Result<(), PaserkError> {
        let (version, type_name, data) =
            parse_header("k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8")?;
        assert_eq!(version, "k4");
        assert_eq!(type_name, "local");
        assert_eq!(data, "cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8");
        Ok(())
    }

    #[test]
    fn test_parse_header_all_versions() -> Result<(), PaserkError> {
        for version in &["k1", "k2", "k3", "k4"] {
            let paserk = format!("{version}.local.data");
            let (v, t, d) = parse_header(&paserk)?;
            assert_eq!(v, *version);
            assert_eq!(t, "local");
            assert_eq!(d, "data");
        }
        Ok(())
    }

    #[test]
    fn test_parse_header_invalid_version() {
        let result = parse_header("k5.local.data");
        assert!(matches!(result, Err(PaserkError::InvalidVersion)));

        let result = parse_header("v4.local.data");
        assert!(matches!(result, Err(PaserkError::InvalidVersion)));
    }

    #[test]
    fn test_parse_header_invalid_format() {
        let result = parse_header("k4.local");
        assert!(matches!(result, Err(PaserkError::InvalidFormat)));

        let result = parse_header("k4");
        assert!(matches!(result, Err(PaserkError::InvalidFormat)));

        let result = parse_header("");
        assert!(matches!(result, Err(PaserkError::InvalidFormat)));
    }

    #[test]
    fn test_parse_header_empty_type() {
        let result = parse_header("k4..data");
        assert!(matches!(result, Err(PaserkError::InvalidHeader)));
    }

    #[test]
    fn test_validate_header_success() -> Result<(), PaserkError> {
        let data = validate_header(
            "k4.local.cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8",
            "k4",
            "local",
        )?;
        assert_eq!(data, "cHFyc3R1dnd4eXp7fH1-f4CBgoOEhYaHiImKi4yNjo8");
        Ok(())
    }

    #[test]
    fn test_validate_header_wrong_version() {
        let result = validate_header("k4.local.data", "k2", "local");
        assert!(matches!(result, Err(PaserkError::InvalidVersion)));
    }

    #[test]
    fn test_validate_header_wrong_type() {
        let result = validate_header("k4.local.data", "k4", "public");
        assert!(matches!(result, Err(PaserkError::InvalidHeader)));
    }

    #[test]
    fn test_make_header() {
        assert_eq!(make_header("k4", "local"), "k4.local.");
        assert_eq!(make_header("k1", "lid"), "k1.lid.");
        assert_eq!(make_header("k3", "public"), "k3.public.");
    }
}
