#[macro_use]
use bellman::groth16::*;
use bls12_381::Bls12;
use group::{ff::Field, Group};
use group::cofactor::CofactorGroup;
use jubjub::{ExtendedPoint, SubgroupPoint};
use masp_primitives::{
    asset_type::AssetType,
    sapling::{Diversifier, ProofGenerationKey},
};
use masp_primitives::convert::AllowedConversion;
use masp_primitives::sapling::ValueCommitment;
use masp_proofs::circuit::convert::Convert;
use masp_proofs::circuit::sapling::Spend;
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use sapling::value::ValueCommitment as OtherValueCommitment;
use sapling::constants::VALUE_COMMITMENT_VALUE_GENERATOR as vb_Sapling;


pub(crate) fn output(rcv_NAM: jubjub::Fr, value: u64) -> AssetType {
    AssetType::new(b"NAM").unwrap()
}

pub(crate) fn convert(vb_nam: SubgroupPoint, rcv_convert: jubjub::Fr, value: u64, V_NAM :u64, V_SAP: u64) -> ValueCommitment {
    let vb_convert = vb_nam*jubjub::Fr::from(V_NAM) - vb_Sapling.double().double().double()*jubjub::Fr::from(V_SAP);

    ValueCommitment {
        asset_generator: ExtendedPoint::from(vb_convert),
        value: value,
        randomness: rcv_convert,
    }
}