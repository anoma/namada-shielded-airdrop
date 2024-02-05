use borsh::{BorshDeserialize, BorshSerialize};
use jubjub::ExtendedPoint;
use redjubjub::{Binding, SpendAuth};
use masp_primitives::transaction::components::{ConvertDescription, OutputDescription};
use sapling::bundle::{SpendDescription};
use masp_primitives::transaction::components::sapling::{Authorized as MaspAuthorized, Authorization as MaspAuthorization, MapAuth};
use masp_primitives::sapling::redjubjub as masp_jubjub;
use sapling::bundle::{Authorized as SapAuthorized, Authorization as SapAuthorization};
use core::fmt::Debug;
use std::hash::Hash;
use sapling::builder::{InProgressProofs, InProgressSignatures, InProgress};
use crate::builder::GROTH_PROOF_SIZE;

pub type GrothProofBytes = [u8; GROTH_PROOF_SIZE];

#[derive(Clone, Debug)]
pub struct AirdropBundle<MA, SA>
    where
        MA: MaspAuthorization,
        SA: SapAuthorization,
{
    pub shielded_spends: Vec<SpendDescription<SA>>,
    pub shielded_converts: Vec<ConvertDescription<MA::Proof>>,
    pub shielded_outputs: Vec<OutputDescription<MA::Proof>>,
    pub value_balance: ExtendedPoint,
    pub sap_authorization: SA,
    pub masp_authorization: MA,

}

impl<MA: MaspAuthorization + PartialEq + BorshSerialize + BorshDeserialize, SA: SapAuthorization> AirdropBundle<MA,SA> {
    pub fn map_authorization_Masp<
        B: MaspAuthorization + PartialEq + BorshSerialize + BorshDeserialize,
        F: MapAuth<MA, B>,
    >(
        self,
        f: F,
    ) -> AirdropBundle<B, SA> {
        let mut temp_bundle = self.clone();
        temp_bundle.shielded_converts = self
            .shielded_converts
            .into_iter()
            .map(|c| ConvertDescription {
                cv: c.cv,
                anchor: c.anchor,
                zkproof: f.map_proof(c.zkproof),
            })
            .collect();
        temp_bundle.shielded_outputs = self
            .shielded_outputs
            .into_iter()
            .map(|o| OutputDescription {
                cv: o.cv,
                cmu: o.cmu,
                ephemeral_key: o.ephemeral_key,
                enc_ciphertext: o.enc_ciphertext,
                out_ciphertext: o.out_ciphertext,
                zkproof: f.map_proof(o.zkproof),
            })
            .collect();
        temp_bundle.masp_authorization = f.map_authorization(self.masp_authorization);
        temp_bundle
    }

    pub fn map_authorization_Sap<
        R,
        B: SapAuthorization
    >(
        self,
        mut context: R,
        spend_proof: impl Fn(&mut R, SA::SpendProof) -> B::SpendProof,
        auth_sig: impl Fn(&mut R, SA::AuthSig) -> B::AuthSig,
        auth: impl FnOnce(&mut R, SA) -> B,
    ) -> AirdropBundle<MA, B> {
        let mut temp_bundle = self.clone();
        temp_bundle.shielded_spends = self
            .shielded_spends
            .into_iter()
            .map(|d| SpendDescription::from_parts(
                *d.cv(),
                *d.anchor(),
                *d.nullifier(),
                *d.rk(),
                spend_proof(&mut context, d.zkproof()),
                auth_sig(&mut context, d.spend_auth_sig()),
            )
            )
            .collect();
        temp_bundle.sap_authorization =  auth(&mut context, self.sap_authorization);
        temp_bundle
    }
}