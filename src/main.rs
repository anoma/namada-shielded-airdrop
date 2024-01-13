use std::ops::Mul;
use ff::Field;
use group::cofactor::CofactorGroup;
use group::Group;
use jubjub::{ExtendedPoint, SubgroupPoint};
use jubjub::Fr as Fr;
use jubjub::Fq as Fq;
use masp_primitives::asset_type::AssetType;
use masp_primitives::constants;

use masp_primitives::convert::AllowedConversion;
use rand_core::{RngCore, SeedableRng};
use rand_xorshift::XorShiftRng;
use sapling::value::ValueSum;
use masp_primitives::transaction::components::ValueSum as MaspValueSum;
use crate::sapling_spend::ConvertToValueCommitment;
use masp_primitives::constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR as R_MASP;
use sapling::constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR as R_Sapling;
use sapling::constants::VALUE_COMMITMENT_VALUE_GENERATOR as vb_Sapling;

mod sapling_spend;
mod MASP_output;

fn main() {
    let mut rng_sap = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let mut rng_masp = XorShiftRng::from_seed([
        0x00, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);
    let mut rng_convert = XorShiftRng::from_seed([
        0x59, 0x00, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let rcv_convert = Fr::random(rng_convert);
    let rcv_NAM = Fr::random(rng_masp);
    let rcv_sapling = Fr::random(rng_sap);
    let value_sapling = 8;
    let value_NAM = 8;
    let value_mint = 1;
    let V_NAM: u64 = 1;
    let V_SAP: u64 = 1;

    let cv_sapling = sapling_spend::sapling_commitment(rcv_sapling, value_sapling);
    let nam_type = MASP_output::output(rcv_NAM, value_NAM);
    let cv_NAM = nam_type.value_commitment(value_NAM, rcv_NAM).commitment();
    let vb_nam = nam_type.value_commitment_generator();  // Has the *8
    let cv_mint = MASP_output::convert(vb_nam, rcv_convert, value_mint, V_NAM, V_SAP).commitment();

    // cofactor check
    assert_eq!(cv_NAM, vb_nam * jubjub::Fr::from(value_NAM) + R_MASP * rcv_NAM);
    assert_eq!(cv_sapling, vb_Sapling * jubjub::Fr::from(value_sapling) + R_Sapling * rcv_sapling);
    assert_eq!(cv_mint, (vb_nam*jubjub::Fr::from(V_NAM) - vb_Sapling.double().double().double()*(jubjub::Fr::from(V_SAP)))*jubjub::Fr::from(value_mint*8) + R_MASP * rcv_convert);
    assert_eq!(cv_sapling.double().double().double(), vb_Sapling * jubjub::Fr::from(value_sapling*8) + R_Sapling * rcv_sapling* jubjub::Fr::from(8));
    // Calculate Randomness renormailzation factor
    let N:SubgroupPoint = (R_MASP)*rcv_sapling - (R_Sapling)*(rcv_sapling * jubjub::Fr::from(8));
    let bvk:SubgroupPoint  = cv_sapling.double().double().double()+ cv_mint - cv_NAM + N;

    let bvk_2:SubgroupPoint  = vb_nam * Fr::from(8*value_mint*V_NAM-value_NAM)+
                               vb_Sapling*Fr::from(value_sapling-8*value_mint*V_SAP) +
                               R_MASP*(rcv_convert+rcv_sapling-rcv_NAM);

    assert_eq!(bvk_2, bvk);
}
