use bellman::groth16::*;
use bls12_381::Bls12;
use group::ff::Field;
use jubjub::{ExtendedPoint, Fr, SubgroupPoint};
use masp_primitives::sapling::ValueCommitment;
use rand::{Rng, RngCore, SeedableRng};
use sapling::{
    circuit::{Spend, ValueCommitmentOpening},
    keys::ExpandedSpendingKey,
    value::NoteValue,
    Diversifier,
};
use rand_xorshift::XorShiftRng;


pub(crate) fn sapling_commitment (rcv_sapling: jubjub::Fr, value: u64) -> SubgroupPoint {
    sapling::constants::VALUE_COMMITMENT_VALUE_GENERATOR* jubjub::Fr::from(value) + sapling::constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR * rcv_sapling
}
// Define a trait for the conversion
pub trait ConvertToValueCommitment {
    fn convert_to_masp_vc(&self) -> ValueCommitment;
}

// Implement the trait for ValueCommitmentOpening
impl ConvertToValueCommitment for ValueCommitmentOpening {
    fn convert_to_masp_vc(&self) -> ValueCommitment {
        // Implement the conversion logic here
        let asset_generator: ExtendedPoint = ExtendedPoint::from(sapling::constants::VALUE_COMMITMENT_VALUE_GENERATOR);
        let value: u64 = self.value.inner();
        let randomness: Fr = self.randomness;

        ValueCommitment {
            asset_generator,
            value,
            randomness,
        }
    }
}