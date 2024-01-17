use bellman::groth16::*;
use bellman::SynthesisError;
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
const TREE_DEPTH: usize = 32;


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

pub fn sapling_spend_circuit(rcv_sapling: jubjub::Fr, value: u64) -> Result<Proof<Bls12>, SynthesisError> {
    let mut rng = XorShiftRng::from_seed([
        0x59, 0x62, 0xbe, 0x3d, 0x76, 0x3d, 0x31, 0x8d, 0x17, 0xdb, 0x37, 0x32, 0x54, 0x06, 0xbc,
        0xe5,
    ]);

    let groth_params = generate_random_parameters::<Bls12, _, _>(
        Spend {
            value_commitment_opening: None,
            proof_generation_key: None,
            payment_address: None,
            commitment_randomness: None,
            ar: None,
            auth_path: vec![None; TREE_DEPTH],
            anchor: None,
        },
        &mut rng,
    )
        .unwrap();
    let value_commitment = ValueCommitmentOpening {
        value: NoteValue::from_raw(value),
        randomness: jubjub::Fr::random(&mut rng),
    };

    let sk: [u8; 32] = rng.gen();
    let expsk = ExpandedSpendingKey::from_spending_key(&sk);

    let proof_generation_key = expsk.proof_generation_key();

    let viewing_key = proof_generation_key.to_viewing_key();

    let payment_address = loop {
        let diversifier = {
            let mut d = [0; 11];
            rng.fill_bytes(&mut d);
            Diversifier(d)
        };

        if let Some(p) = viewing_key.to_payment_address(diversifier) {
            break p;
        }
    };

    let commitment_randomness = rcv_sapling;
    let auth_path =
        vec![Some((bls12_381::Scalar::random(&mut rng), rng.next_u32() % 2 != 0)); TREE_DEPTH];
    let ar = jubjub::Fr::random(&mut rng);
    let anchor = bls12_381::Scalar::random(&mut rng);

    create_random_proof(
        Spend {
            value_commitment_opening: Some(value_commitment.clone()),
            proof_generation_key: Some(proof_generation_key.clone()),
            payment_address: Some(payment_address),
            commitment_randomness: Some(commitment_randomness),
            ar: Some(ar),
            auth_path: auth_path.clone(),
            anchor: Some(anchor),
        },
        &groth_params,
        &mut rng,
    )
}