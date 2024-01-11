use std::ops::Mul;
use ff::Field;
use group::cofactor::CofactorGroup;
use jubjub::SubgroupPoint;
use jubjub::Fr as Fr;
use jubjub::Fq as Fq;

use masp_primitives::asset_type::AssetType;

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
    let value_sapling = 10;
    let value_NAM = 10;
    let value_mint = 10;
    let V_NAM: u64 = 1;
    let V_SAP: u64 = 1;

    let cv_sapling = sapling_spend::spend(rcv_sapling, value_sapling).convert_to_masp_vc().commitment();
    let cv_NAM_wrap = MASP_output::output(rcv_NAM, value_NAM);
    let cv_NAM = cv_NAM_wrap.commitment();
    let cv_mint = MASP_output::convert(rcv_convert, value_mint, V_NAM, V_SAP).commitment();

    // Calculate Randomness renormailzation factor
    let N = R_MASP*rcv_sapling - R_Sapling*rcv_sapling;
    let bvk = cv_sapling + cv_mint - cv_NAM + N;
    let vb_nam = cv_NAM_wrap.asset_generator.into_subgroup().unwrap();
    // Calucalte bvk from rcv values
    let bvk_2  = vb_nam*Fr::from(value_sapling -value_mint*V_SAP) + vb_Sapling*Fr::from(value_mint*V_NAM-value_NAM) + R_MASP*(-rcv_NAM+rcv_convert+rcv_sapling) ;

    // Todo:
    // bvk_2 is currently not matching with bvk.
    //println!("{:?}", bvk_2);
    //println!("{:?}", bvk_3);
    assert_eq!(vb_Sapling, vb_Sapling * Fr::one());

}
