#[macro_use]
use bellman::groth16::*;
use bls12_381::Bls12;
use group::{ff::Field, Group};
use jubjub::ExtendedPoint;
use masp_primitives::{
    asset_type::AssetType,
    sapling::{Diversifier, ProofGenerationKey},
};
use masp_primitives::sapling::ValueCommitment;
use masp_proofs::circuit::sapling::Spend;
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use sapling::value::ValueCommitment as OtherValueCommitment;

pub(crate) fn output(rcv_NAM: jubjub::Fr) -> ValueCommitment {
    let value_commitment = AssetType::new(b"NAM")
        .unwrap()
        .value_commitment(1,rcv_NAM);

    value_commitment
}

pub(crate) fn convert(rcv_convert: jubjub::Fr) -> ValueCommitment {

    let V_NAM: u64 = 1;
    let V_SAP: u64 = 1;  //Gets negated afterwards

    let vb_nam = AssetType::new(b"NAM").unwrap().asset_generator();
    let vb_sapling = sapling::constants::VALUE_COMMITMENT_VALUE_GENERATOR;
    let vb_convert = vb_nam*jubjub::Scalar::from(0) + vb_sapling*(-jubjub::Scalar::from(0));

    ValueCommitment {
        asset_generator: vb_convert,
        value: 1,
        randomness: rcv_convert,
    }
}