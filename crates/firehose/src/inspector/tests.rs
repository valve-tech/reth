//! Tests for [`crate::inspector`], split by the behaviour under test. Shared fixtures live in
//! [`support`]; [`scenario`] holds the SELFDESTRUCT harness [`selfdestruct`] drives.

mod balance;
mod call_data;
mod gas;
mod gas_boundary;
mod native_log;
mod precompile;
mod scenario;
mod selfdestruct;
mod support;
