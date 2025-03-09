// MiniSafe MicroVM Implementation
// Copyright (c) 2024-2025 The Mapleseed Inc.
// Licensed under GPL-3.0 License

//! # MiniSafe MicroVM Library
//!
//! This library provides the core functionality for the MiniSafe MicroVM system.
//! It implements a security-hardened, lightweight micro virtual machine with:
//! - W^X (Write XOR Execute) memory protection
//! - Data Guards for preventing information leakage
//! - Network namespace isolation with full network stack control
//! - GitHub integration for CI/CD workflows
//! - Hot-reloading capabilities
//! - Fully concurrent execution model
//!
//! The library is designed to be used as a standalone library or through the
//! provided CLI interface.

// Re-export the VMcore module contents
pub use crate::VMcore::*;

// Include the VMcore module
pub mod VMcore;

// CLI module (not public)
mod cli;

// Export the CLI run function for bin usage
pub use cli::run; 