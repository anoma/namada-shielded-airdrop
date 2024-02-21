use core::fmt::Debug;
use borsh::{BorshDeserialize, BorshSerialize};
use group::GroupEncoding;
use jubjub::{SubgroupPoint};
use masp_note_encryption::EphemeralKeyBytes;
use masp_primitives::transaction::components::sapling::{Authorization as MaspAuth, MapAuth};
use masp_primitives::transaction::components::sapling::builder::Error as MaspErr;
use masp_primitives::transaction::components::{ConvertDescription, I128Sum, OutputDescription};
use sapling::{builder::{Error, SpendInfo}, Nullifier};
use rand_core::RngCore;
use sapling::bundle::{Authorization, Authorized, SpendDescription};
use redjubjub::{Signature, SpendAuth};
use jubjub;
use sapling::prover::{OutputProver, SpendProver};
use sapling::value::{ValueCommitment, ValueCommitTrapdoor};
use masp_primitives::constants::{VALUE_COMMITMENT_RANDOMNESS_GENERATOR as R_MASP, VALUE_COMMITMENT_RANDOMNESS_GENERATOR};
use masp_primitives::sapling::redjubjub::{PrivateKey, PublicKey};
use sapling::constants::VALUE_COMMITMENT_RANDOMNESS_GENERATOR as R_Sapling;
use masp_primitives::transaction::components::sapling::Authorized as MASPAuthorized;
use sapling::bundle::GrothProofBytes;
pub(crate) const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;
const MIN_SHIELDED_OUTPUTS: usize = 2;

pub const MAX_MONEY: u64 = u64::MAX;
#[derive(Clone, Debug)]
pub struct AirdropBundle<MA: MaspAuth+ PartialEq + BorshSerialize + BorshDeserialize> {
    spends: Vec<SpendDescription<Authorized>>,
    converts: Vec<ConvertDescription<GrothProofBytes>>,
    outputs: Vec<OutputDescription<GrothProofBytes>>,
    renomralizators: Vec<SubgroupPoint>,
    authorization: MA::AuthSig,
}

impl<MA> AirdropBundle<MA>
    where
        MA: MaspAuth<Proof = GrothProofBytes, AuthSig = ()> + std::cmp::PartialEq + borsh::BorshSerialize + borsh::BorshDeserialize
{
    /// initialize the airdrop tool with the sapling spend commitment tree anchor
    pub fn init() -> Self {
        AirdropBundle {
            spends: vec![],
            converts: vec![],
            outputs: vec![],
            renomralizators: vec![],
            authorization: (),
        }
    }
    pub fn add_spend_description(
        &mut self,
        cv: ValueCommitment,
        anchor: bls12_381::Scalar,
        nullifier: Nullifier,
        rk: redjubjub::VerificationKey<SpendAuth>,
        zkproof: GrothProofBytes,
        spend_auth_sig: redjubjub::Signature<SpendAuth>,
    ) -> Result<(), Error> {
        self.spends.push(SpendDescription::from_parts(
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
        ));
        Ok(())
    }

    pub fn add_output_description(
        &mut self,
        cv: jubjub::ExtendedPoint,
        cmu: bls12_381::Scalar,
        ephemeral_key: EphemeralKeyBytes,
        enc_ciphertext: [u8; 580 + 32],
        out_ciphertext: [u8; 80],
        zkproof: GrothProofBytes,
    ) -> Result<(), MaspErr> {
        self.outputs.push(OutputDescription { cv, cmu, ephemeral_key, enc_ciphertext, out_ciphertext, zkproof });
        Ok(())
    }

    pub fn add_convert_description(
        &mut self,
        cv: jubjub::ExtendedPoint,
        anchor: bls12_381::Scalar,
        zkproof: [u8; GROTH_PROOF_SIZE],
    ) -> Result<(), MaspErr> {
        // Consistency check: all anchors must equal the first one
        self.converts.push(ConvertDescription { cv, anchor, zkproof });
        Ok(())
    }
}
impl<MA> AirdropBundle<MA>
        where
            MA: MaspAuth<Proof = GrothProofBytes, AuthSig = MASPAuthorized> + std::cmp::PartialEq + borsh::BorshSerialize + borsh::BorshDeserialize
    {
    pub fn apply_signatures<R: RngCore>(
        &mut self,
        rcv_sap: ValueCommitTrapdoor,
        rcv_nam: jubjub::Fr,
        rcv_cnvrt: jubjub::Fr,
        rng: &mut R,
        sighash: &[u8; 32],
    ) {
        let N:SubgroupPoint = (R_MASP)*rcv_sap.inner() - (R_Sapling)*(rcv_sap.inner() * jubjub::Fr::from(8));
        self.renomralizators.push(N);
        let bsk = PrivateKey(rcv_sap.inner() - rcv_nam + rcv_cnvrt);
        let bvk = PublicKey::from_private(&bsk, VALUE_COMMITMENT_RANDOMNESS_GENERATOR);

        let mut data_to_be_signed = [0u8; 64];
        data_to_be_signed[0..32].copy_from_slice(&bvk.0.to_bytes());
        data_to_be_signed[32..64].copy_from_slice(&sighash[..]);

        // Sign
        let signature = bsk.sign(
            &data_to_be_signed,
            rng,
            VALUE_COMMITMENT_RANDOMNESS_GENERATOR,
        );
        self.authorization =  MASPAuthorized { binding_sig: signature };
    }

}