#[macro_use]
use bellman::groth16::*;
use bls12_381::Bls12;
use group::{ff::Field, Group};
use group::cofactor::CofactorGroup;
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

pub(crate) fn output(rcv_NAM: jubjub::Fr, value: u64) -> ValueCommitment {
    AssetType::new(b"NAM")
        .unwrap()
        .value_commitment(value,rcv_NAM)
}

pub(crate) fn convert(rcv_convert: jubjub::Fr, value: u64, V_NAM :u64, V_SAP: u64) -> ValueCommitment {
    let vb_nam = AssetType::new(b"NAM").unwrap().asset_generator();
    let vb_sapling = sapling::constants::VALUE_COMMITMENT_VALUE_GENERATOR;
    let vb_convert = vb_nam*jubjub::Fr::from(V_NAM) - vb_sapling*(jubjub::Fr::from(V_SAP));

    ValueCommitment {
        asset_generator: vb_convert,
        value: value,
        randomness: rcv_convert,
    }
}