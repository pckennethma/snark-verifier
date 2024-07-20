//! Proof systems `snark-verifier` supports

#[cfg(not(feature = "halo2-scroll"))]
// halo2-scroll uses mv-lookup and the system has not been updated to support it
pub mod halo2;
