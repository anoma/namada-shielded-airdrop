use bellman::groth16::*;
use bls12_381::Bls12;
use group::ff::Field;
use jubjub::{ExtendedPoint, Fr};
use masp_primitives::sapling::ValueCommitment;
use rand::{Rng, RngCore, SeedableRng};
use sapling::{
    circuit::{Spend, ValueCommitmentOpening},
    keys::ExpandedSpendingKey,
    value::NoteValue,
    Diversifier,
};
use rand_xorshift::XorShiftRng;


pub(crate) fn spend (rcv_sapling: jubjub::Fr) -> ValueCommitmentOpening {
    let value_commitment = ValueCommitmentOpening {
        value: NoteValue::from_raw(1),
        randomness: rcv_sapling,
    };
    value_commitment
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