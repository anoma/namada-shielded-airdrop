use core::fmt::Debug;
use std::io::Write;
use std::iter;
use std::sync::mpsc::Sender;
use bls12_381::Bls12;
use borsh::{BorshDeserialize, BorshSerialize};
use ff::Field;
use group::GroupEncoding;
use jubjub::{ExtendedPoint, Fr};
use masp_primitives::merkle_tree::MerklePath;
use masp_primitives::sapling::Node;
use masp_primitives::sapling::Note;
use masp_primitives::convert::AllowedConversion;
use masp_primitives::consensus;
use masp_primitives::consensus::BlockHeight;
use masp_primitives::transaction::components::sapling::builder::{ConvertDescriptionInfo, SaplingMetadata, Unauthorized as MASPUnauthorized};
use masp_primitives::transaction::components::sapling::builder::SaplingBuilder;
use masp_primitives::transaction::components::sapling::builder::SaplingOutputInfo;
use masp_primitives::transaction::components::sapling::{Authorization as MaspAuth, MapAuth};
use masp_primitives::sapling::util::generate_random_rseed;
use masp_primitives::transaction::components::sapling::builder::SpendDescriptionInfo;
use masp_primitives::transaction::components::amount::ValueSum;
use masp_primitives::transaction::components::sapling::builder::Error as MaspErr;
use masp_primitives::transaction::components::{ConvertDescription, I128Sum, OutputDescription};
use masp_primitives::asset_type::AssetType;
use masp_primitives::keys::OutgoingViewingKey;
use masp_primitives::memo::MemoBytes;
use masp_primitives::sapling::note_encryption::sapling_note_encryption;
use masp_primitives::sapling::PaymentAddress;
use masp_primitives::sapling::prover::TxProver;
use masp_primitives::transaction::builder::Progress;
use masp_primitives::transaction::components::sapling::{Bundle, GrothProofBytes};
use rand::prelude::SliceRandom;
use sapling::{zip32::ExtendedSpendingKey, Diversifier, MerklePath as SapMerklePath, Note as SapNote, builder::{Error, SpendInfo}, value::ValueSum as SapValueSum, Nullifier};
use rand_core::RngCore;
use sapling::builder::{Builder, OutputInfo, SigningMetadata, SigningParts, UnauthorizedBundle};
use sapling::bundle::{Authorization, SpendDescription};
use rand::{rngs::StdRng, SeedableRng};
use redjubjub::SpendAuth;
use sapling::prover::{OutputProver, SpendProver};
use sapling::value::{ValueCommitment, ValueCommitTrapdoor};

pub(crate) const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;
const MIN_SHIELDED_OUTPUTS: usize = 2;

pub const MAX_MONEY: u64 = u64::MAX;

/// Metadata about a transaction created by a [`SaplingBuilder`].
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AirdropMetadata {
    spend_indices: Vec<usize>,
    convert_indices: Vec<usize>,
    output_indices: Vec<usize>,
}

impl AirdropMetadata {
    pub fn empty() -> Self {
        AirdropMetadata {
            spend_indices: vec![],
            convert_indices: vec![],
            output_indices: vec![],
        }
    }

    /// Returns the index within the transaction of the [`SpendDescription`] corresponding
    /// to the `n`-th call to [`SaplingBuilder::add_spend`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first spend
    /// they added (via the first call to [`SaplingBuilder::add_spend`]) is the first
    /// [`SpendDescription`] in the transaction.
    pub fn spend_index(&self, n: usize) -> Option<usize> {
        self.spend_indices.get(n).copied()
    }

    /// Returns the index within the transaction of the [`OutputDescription`] corresponding
    /// to the `n`-th call to [`SaplingBuilder::add_output`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first output
    /// they added (via the first call to [`SaplingBuilder::add_output`]) is the first
    /// [`OutputDescription`] in the transaction.
    pub fn output_index(&self, n: usize) -> Option<usize> {
        self.output_indices.get(n).copied()
    }
    /// Returns the index within the transaction of the [`ConvertDescription`] corresponding
    /// to the `n`-th call to [`SaplingBuilder::add_convert`].
    ///
    /// Note positions are randomized when building transactions for indistinguishability.
    /// This means that the transaction consumer cannot assume that e.g. the first output
    /// they added (via the first call to [`SaplingBuilder::add_output`]) is the first
    /// [`ConvertDescription`] in the transaction.
    pub fn convert_index(&self, n: usize) -> Option<usize> {
        self.convert_indices.get(n).copied()
    }
}

#[derive(Clone, Debug)]
pub struct AirdropBundle<A, MA>
    where
        A: Authorization,
        MA: MaspAuth + PartialEq + BorshSerialize + BorshDeserialize,
{
    pub shielded_spends: Vec<SpendDescription<A>>,
    pub shielded_converts: Vec<ConvertDescription<MA::Proof>>,
    pub shielded_outputs: Vec<OutputDescription<MA::Proof>>,
    pub value_balance: ExtendedPoint,
    pub authorization: A,
}

pub struct AirdropBuilder<P, A: Authorization, MA: MaspAuth> {
    params: P,
    spend_anchor: jubjub::Base,
    target_height: BlockHeight,
    value_balance: ExtendedPoint,
    convert_anchor: Option<bls12_381::Scalar>,
    spends: Vec<SpendDescription<A>>,
    converts: Vec<ConvertDescription<MA::Proof>>,
    outputs: Vec<OutputDescription<MA::Proof>>,
}
impl<P, A, MA> AirdropBuilder<P, A, MA>
    where
        P: consensus::Parameters,
        A: Authorization + Clone,
        MA: MaspAuth + PartialEq + BorshSerialize + BorshDeserialize
{
    /// initialize the airdrop tool with the sapling spend commitment tree anchor
    pub fn init(params: P, target_height: BlockHeight, anchor: jubjub::Base) -> Self{
        AirdropBuilder {
            params,
            spend_anchor: anchor,
            target_height,
            value_balance: ExtendedPoint::identity(),
            convert_anchor: None,
            spends: vec![],
            converts: vec![],
            outputs: vec![],
        }
    }
    pub fn add_spend_description<R: RngCore>(
        &mut self,
        cv: ValueCommitment,
        anchor: bls12_381::Scalar,
        nullifier: Nullifier,
        rk: redjubjub::VerificationKey<SpendAuth>,
        zkproof: A::SpendProof,
        spend_auth_sig: A::AuthSig,
    )-> Result<(), Error> {
        let spend_description: SpendDescription<A> = SpendDescription::from_parts(
            cv,
            anchor,
            nullifier,
            rk,
            zkproof,
            spend_auth_sig,
        );
        self.spends.push(spend_description.clone());
        let cv_sap: ExtendedPoint = spend_description.cv().as_inner().double().double().double();
        self.value_balance += cv_sap;
        Ok(())
    }

    pub fn add_output_description<Pr: TxProver, R: RngCore+ rand_core::CryptoRng>(
        &mut self,
        mut rng: R,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        asset_type: AssetType,
        value: u64,
        memo: MemoBytes,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
    ) -> Result<(), MaspErr> {
        let g_d = to.g_d().ok_or(MaspErr::InvalidAddress)?;
        if value > MAX_MONEY {
            return Err(MaspErr::InvalidAmount);
        }
        let rseed = generate_random_rseed(&self.params, self.target_height, &mut rng);

        let note = Note {
            g_d,
            pk_d: *to.pk_d(),
            value,
            rseed,
            asset_type,
        };
        let encryptor = sapling_note_encryption::<P>(ovk, note, to, memo);

        let (zkproof, cv) = prover.output_proof(
            ctx,
            *encryptor.esk(),
            to,
            note.rcm(),
            note.asset_type,
            note.value,
        );

        let cmu = note.cmu();

        let enc_ciphertext = encryptor.encrypt_note_plaintext();
        let out_ciphertext = encryptor.encrypt_outgoing_plaintext(&cv, &cmu, &mut rng);

        let epk = *encryptor.epk();

        let output = OutputDescription {
            cv,
            cmu,
            ephemeral_key: epk.to_bytes().into(),
            enc_ciphertext,
            out_ciphertext,
            zkproof,
        };

        self.value_balance -= cv;

        self.outputs.push(output.clone());
        Ok(())
    }

    pub fn add_convert_description<Pr: TxProver, R: RngCore+ rand_core::CryptoRng>(
        &mut self,
        allowed: AllowedConversion,
        value: u64,
        merkle_path: MerklePath<Node>,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
    ) -> Result<(), MaspErr> {
        // Consistency check: all anchors must equal the first one

        let node = allowed.commitment();
        if let Some(anchor) = self.convert_anchor {
            let path_root: bls12_381::Scalar = merkle_path.root(node).into();
            if path_root != anchor {
                return Err(MaspErr::AnchorMismatch);
            }
        } else {
            self.convert_anchor = Some(merkle_path.root(node).into())
        }

        let (zkproof, cv) = prover
            .convert_proof(
                ctx,
                allowed.clone(),
                value,
                self.convert_anchor.unwrap(),
                merkle_path,
            )
            .map_err(|_| MaspErr::ConvertProof)?;
        let convert = ConvertDescription {
            cv,
            anchor: self.convert_anchor.unwrap(),
            zkproof,
        };
        self.value_balance += cv;
        self.converts.push(convert);
        Ok(())
    }


    pub fn build<Pr: TxProver, R: RngCore, V: TryFrom<i64>>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        mut rng: R,
        target_height: BlockHeight,
    ) -> Result<Option<AirdropBundle<UnauthorizedBundle<V>, MASPUnauthorized>>, Error>{
        let value_balance = self.value_balance();
        let params = self.params;
        let mut indexed_spends: Vec<_> = self.spends.into_iter().enumerate().collect();
        let mut indexed_converts: Vec<_> = self.converts.into_iter().enumerate().collect();
        let mut indexed_outputs: Vec<_> = self
            .outputs
            .iter()
            .enumerate()
            .map(|(i, o)| Some((i, o)))
            .collect();

        // Set up the transaction metadata that will be used to record how
        // inputs and outputs are shuffled.
        let mut tx_metadata = AirdropMetadata::empty();
        tx_metadata.spend_indices.resize(indexed_spends.len(), 0);
        tx_metadata
            .convert_indices
            .resize(indexed_converts.len(), 0);
        tx_metadata.output_indices.resize(indexed_outputs.len(), 0);

        // Pad Sapling outputs
        if !indexed_spends.is_empty() {
            while indexed_outputs.len() < MIN_SHIELDED_OUTPUTS {
                indexed_outputs.push(None);
            }
        }

        // Randomize order of inputs and outputs
        indexed_spends.shuffle(&mut rng);
        indexed_converts.shuffle(&mut rng);
        indexed_outputs.shuffle(&mut rng);


        let bundle = if self.spends.is_empty() && self.outputs.is_empty() {
            None
        } else {
            Some(Bundle {
                shielded_spends: self.spends,
                shielded_converts: self.converts,
                shielded_outputs: self.outputs,
                value_balance,
                authorization: MASPUnauthorized { tx_metadata },
            })
        };

        Ok(bundle)
    }

}