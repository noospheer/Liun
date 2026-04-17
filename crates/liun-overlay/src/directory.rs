//! # Relay Directory
//!
//! A TOML file listing known relays in a deterministic order.
//! Both peers in a bootstrap session MUST have the same directory
//! (same order, same URLs), since shares are assigned to relays by index.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// One entry in the directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayEntry {
    /// Base URL, e.g. `http://relay.example.com:8080`.
    pub url: String,
    /// Human-readable operator name (informational only).
    #[serde(default)]
    pub operator: String,
    /// Jurisdiction / country hint (informational only).
    #[serde(default)]
    pub jurisdiction: String,
}

/// A parsed relay directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Directory {
    /// List of relays in deterministic order.
    #[serde(rename = "relay", default)]
    pub relays: Vec<RelayEntry>,
}

impl Directory {
    /// Load a directory from a TOML file path.
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, DirectoryError> {
        let contents = std::fs::read_to_string(path.as_ref())
            .map_err(DirectoryError::Io)?;
        Self::from_toml(&contents)
    }

    /// Parse from a TOML string.
    pub fn from_toml(s: &str) -> Result<Self, DirectoryError> {
        let dir: Self = toml::from_str(s).map_err(DirectoryError::Parse)?;
        if dir.relays.is_empty() {
            return Err(DirectoryError::Empty);
        }
        Ok(dir)
    }

    /// Number of relays.
    pub fn len(&self) -> usize { self.relays.len() }

    /// True if no relays.
    pub fn is_empty(&self) -> bool { self.relays.is_empty() }
}

#[derive(Debug)]
pub enum DirectoryError {
    Io(std::io::Error),
    Parse(toml::de::Error),
    Empty,
}

impl std::fmt::Display for DirectoryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "reading relays.toml: {e}"),
            Self::Parse(e) => write!(f, "parsing relays.toml: {e}"),
            Self::Empty => write!(f, "relays.toml contains no relays"),
        }
    }
}

impl std::error::Error for DirectoryError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let toml = r#"
            [[relay]]
            url = "http://relay1.example.com:8080"
            operator = "alice"
            jurisdiction = "DE"

            [[relay]]
            url = "http://relay2.example.org:8080"
            operator = "bob"
        "#;
        let d = Directory::from_toml(toml).unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(d.relays[0].url, "http://relay1.example.com:8080");
        assert_eq!(d.relays[0].operator, "alice");
        assert_eq!(d.relays[0].jurisdiction, "DE");
        assert_eq!(d.relays[1].jurisdiction, ""); // default empty
    }

    #[test]
    fn parse_empty_rejected() {
        assert!(matches!(Directory::from_toml(""), Err(DirectoryError::Empty)));
    }

    #[test]
    fn parse_invalid_rejected() {
        assert!(Directory::from_toml("not = [toml").is_err());
    }
}
