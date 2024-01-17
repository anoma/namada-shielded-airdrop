#![allow(clippy::new_without_default)]

use bellman::{gadgets::multipack, groth16::Proof};
use bls12_381::Bls12;
use group::{Curve, GroupEncoding};
use masp_primitives::{
    sapling::redjubjub::{PublicKey, Signature},
    transaction::components::I128Sum,
};

struct AirdropVerificationContext {
    cv_sum: jubjub::ExtendedPoint,
    N: jubjub::ExtendedPoint,
}

impl AirdropVerificationContext {
    fn new() -> Self {
        AirdropVerificationContext{
            cv_sum: jubjub::ExtendedPoint::identity(),
            N: jubjub::ExtendedPoint::identity(),
        }
    }
    /// Perform consensus checks on a Sapling SpendDescription, while
    /// accumulating its value commitment inside the context for later use.
    fn check_spend() {

    }

    /// Perform consensus checks on a Convert SpendDescription, while
    /// accumulating its value commitment inside the context for later use.
    fn check_convert() {

    }

    /// Perform consensus checks on a Sapling OutputDescription, while
    /// accumulating its value commitment inside the context for later use.
    fn check_output() {

    }

    /// Perform consensus checks on the valueBalance and bindingSig parts of a
    /// Sapling transaction. All SpendDescriptions and OutputDescriptions must
    /// have been checked before calling this function.
    fn final_check() {

    }
}