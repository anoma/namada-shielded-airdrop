use ff::Field;
use group::GroupEncoding;
use jubjub::{ExtendedPoint, SubgroupPoint};
use jubjub::Fr as Fr;
use masp_primitives::asset_type::AssetType;
use masp_primitives::sapling::redjubjub::{PrivateKey, PublicKey, Signature};
use rand_core::OsRng;
use masp_primitives::constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR as R_MASP;
use masp_primitives::sapling::ValueCommitment;
use sapling::constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR as R_Sapling;
use sapling::constants::VALUE_COMMITMENT_VALUE_GENERATOR as vb_Sapling;

fn main() {
}

// Sapling value commitment
pub fn sapling_commitment (rcv_sapling: jubjub::Fr, value: u64) -> SubgroupPoint {
    vb_Sapling* jubjub::Fr::from(value) + R_Sapling * rcv_sapling
}

// Convert value commitment
pub fn convert_commitment(vb_nam: SubgroupPoint, rcv_convert: jubjub::Fr, value: u64, v_nam:u64, v_sap: u64) -> SubgroupPoint {
    let vb_mint = vb_nam*jubjub::Fr::from(v_nam) - vb_Sapling*jubjub::Fr::from(v_sap);

    ValueCommitment {
        asset_generator: ExtendedPoint::from(vb_mint),
        value: value,
        randomness: rcv_convert,
    }.commitment()
}

// Secret key from trapdoors
pub fn generate_bsk(rcv_mint: Fr, rcv_nam: Fr, rcv_sapling: Fr) -> Fr {
    rcv_mint+rcv_sapling- rcv_nam
}

// Binding Signature
pub fn binding_sig(
    bsk: Fr,
    sighash: &[u8; 32],
) -> Result<Signature, ()>{
    // Initialize secure RNG
    let mut rng = OsRng;

    // Grab the current `bsk` from the context
    let bsk = PrivateKey(bsk);

    // Grab the `bvk` using DerivePublic.
    let bvk = PublicKey::from_private(&bsk, R_MASP);

    // Construct signature message
    let mut data_to_be_signed = [0u8; 64];
    data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
    data_to_be_signed[32..64].copy_from_slice(&sighash[..]);

    // Sign
    Ok(bsk.sign(
        &data_to_be_signed,
        &mut rng,
        R_MASP,
    ))
}

// Binding Signature Verification
fn signature_verification(
    sighash_value: &[u8; 32],
    cv_sum: SubgroupPoint,
    binding_sig: Signature,
    binding_sig_verifier: impl FnOnce(PublicKey, [u8; 64], Signature) -> bool,
) -> bool {
    // Obtain current cv_sum from the context
    let bvk = PublicKey(ExtendedPoint::from(cv_sum));
    // Compute the signature's message for bvk/binding_sig
    let mut data_to_be_signed = [0u8; 64];
    data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
    data_to_be_signed[32..64].copy_from_slice(&sighash_value[..]);

    // Verify the binding_sig
    binding_sig_verifier(bvk, data_to_be_signed, binding_sig)
}


// Compute and sum of all value commitments and renormalization facotr. (Acts as public key).
pub fn cv_sum(value_sapling: u64, value_nam: u64, rcv_sapling: Fr, rcv_nam: Fr, rcv_mint: Fr) -> SubgroupPoint {
    let cv_sapling = sapling_commitment(rcv_sapling, value_sapling*8);
    let nam_type = AssetType::new(b"NAM").unwrap();
    let cv_nam = nam_type.value_commitment(value_nam*8, rcv_nam).commitment();
    let vb_nam = nam_type.value_commitment_generator();  // Has the cofactor h_j included
    let cv_mint = convert_commitment(vb_nam, rcv_mint, value_sapling, 1, 1);

    // Calculate Randomness renormailzation factor
    let n_renorm:SubgroupPoint = (R_MASP)*(rcv_sapling) - R_Sapling*(rcv_sapling);

    cv_sapling + cv_mint - cv_nam + n_renorm
}
#[cfg(test)]
mod tests {
    use super::*;
    use rand_xorshift::XorShiftRng;
    use rand_core::SeedableRng;
    use jubjub::Fr;
    use masp_primitives::constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR as R_MASP;
    use rand::Rng;

    #[test]
    fn test_sucessfull_signature_verification() {

        // Generates trapdoor for value commitments
        let rng_sap = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
            0xe5,
        ]);
        let rng_masp = XorShiftRng::from_seed([
            0xf2, 0x84, 0xd7, 0x90, 0xae, 0x2b, 0x15, 0x3c, 0x61, 0x5f, 0x72, 0x49, 0x38, 0xc6, 0x9d,
            0xbc,
        ]);
        let rng_convert = XorShiftRng::from_seed([
            0x5a, 0xa5, 0x2f, 0x47, 0x8c, 0x3d, 0x19, 0xe7, 0x6b, 0x1d, 0xf0, 0x22, 0x73, 0x55, 0x99,
            0xbc,
        ]);
        let rcv_mint = Fr::random(rng_convert);
        let rcv_nam = Fr::random(rng_masp);
        let rcv_sapling = Fr::random(rng_sap);

        // Generates secret key
        let bsk = generate_bsk(rcv_mint, rcv_nam, rcv_sapling);

        // Compute public key (Balanced airdrop case, claiming 1 NAM for 1 ZEC)
        let cv_sum = cv_sum(1,1,rcv_sapling,rcv_nam,rcv_mint);

        // Sign using secret key
        let mut rng = rand::thread_rng();
        let fake_sig_hash_bytes: [u8; 32] = rng.gen();
        let sig = binding_sig(bsk, &fake_sig_hash_bytes);

        // Verify signature using public key
        let result = signature_verification(
            &fake_sig_hash_bytes,
            cv_sum,
            sig.unwrap(),
            |bvk, msg, binding_sig| { bvk.verify_with_zip216(&msg, &binding_sig, R_MASP, true,) }
        );

        assert_eq!(result, true);
    }

    #[test]
    fn test_failed_signature_verification() {
        let rng_sap = XorShiftRng::from_seed([
            0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
            0xe5,
        ]);
        let rng_masp = XorShiftRng::from_seed([
            0xf2, 0x84, 0xd7, 0x90, 0xae, 0x2b, 0x15, 0x3c, 0x61, 0x5f, 0x72, 0x49, 0x38, 0xc6, 0x9d,
            0xbc,
        ]);
        let rng_convert = XorShiftRng::from_seed([
            0x5a, 0xa5, 0x2f, 0x47, 0x8c, 0x3d, 0x19, 0xe7, 0x6b, 0x1d, 0xf0, 0x22, 0x73, 0x55, 0x99,
            0xbc,
        ]);
        let rcv_mint = Fr::random(rng_convert);
        let rcv_nam = Fr::random(rng_masp);
        let rcv_sapling = Fr::random(rng_sap);

        let bsk = generate_bsk(rcv_mint, rcv_nam, rcv_sapling);

        // Not viable airdrop: Claiming 4 NAM for 1 ZEC
        let cv_sum = cv_sum(1,4,rcv_sapling,rcv_nam,rcv_mint);

        let mut rng = rand::thread_rng();
        let fake_sig_hash_bytes: [u8; 32] = rng.gen();
        let sig = binding_sig(bsk, &fake_sig_hash_bytes);

        let result = signature_verification(
            &fake_sig_hash_bytes,
            cv_sum,
            sig.unwrap(),
            |bvk, msg, binding_sig| { bvk.verify_with_zip216(&msg, &binding_sig, R_MASP, true,) }
        );

        assert_eq!(result, false);
    }
}
