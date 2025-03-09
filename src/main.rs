// MiniSafe MicroVM Implementation
// Copyright (c) 2024-2025 The Mapleseed Inc.
// Licensed under GPL-3.0 License

//! # MiniSafe MicroVM
//!
//! A security-hardened, lightweight microVM with advanced features:
//! - W^X (Write XOR Execute) memory protection
//! - Data Guards for preventing information leakage
//! - Network namespace isolation with full network stack control
//! - GitHub integration for CI/CD workflows
//! - Hot-reloading capabilities
//! - Fully concurrent execution model
//!
//! This system is designed for production environments with a focus on
//! security, performance, and ease of deployment.

mod cli;

// Re-export VMcore as a module
pub use crate::VMcore::*;

fn main() {
    // Initialize MicroVM and run CLI
    match cli::run() {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
} 