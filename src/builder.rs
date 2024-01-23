use core::fmt::Debug;
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
use masp_primitives::transaction::components::sapling::builder::{ConvertDescriptionInfo, SaplingMetadata, Unauthorized};
use masp_primitives::transaction::components::sapling::builder::SaplingBuilder;
use masp_primitives::transaction::components::sapling::builder::SaplingOutputInfo;
use masp_primitives::sapling::util::generate_random_rseed;
use masp_primitives::transaction::components::sapling::builder::SpendDescriptionInfo;
use masp_primitives::transaction::components::amount::ValueSum;
use masp_primitives::transaction::components::{ConvertDescription, I128Sum, OutputDescription};
use masp_primitives::asset_type::AssetType;
use masp_primitives::keys::OutgoingViewingKey;
use masp_primitives::memo::MemoBytes;
use masp_primitives::sapling::PaymentAddress;
use masp_primitives::sapling::prover::TxProver;
use masp_primitives::transaction::builder::Progress;
use masp_primitives::transaction::components::sapling::{Bundle, GrothProofBytes};
use rand::prelude::SliceRandom;
use sapling::{zip32::ExtendedSpendingKey, Diversifier, MerklePath as SapMerklePath, Note as SapNote, builder::{Error, SpendInfo}, value::ValueSum as SapValueSum, Nullifier};
use rand_core::RngCore;
use sapling::builder::{Builder, OutputInfo, SigningMetadata, SigningParts};
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


pub struct AirdropBuilder<P, A: Authorization> {
    params: P,
    spend_anchor: jubjub::Base,
    target_height: BlockHeight,
    value_balance: ExtendedPoint,
    convert_anchor: Option<bls12_381::Scalar>,
    spends: Vec<SpendDescription<A>>,
    converts: Vec<ConvertDescriptionInfo>,
    outputs: Vec<SaplingOutputInfo>,
}

impl<P: consensus::Parameters, A: Authorization> AirdropBuilder<P, A> {

    /// initialize the airdrop tool with the sapling spend commitment tree anchor
    pub fn init(params: P, target_height: BlockHeight, anchor: jubjub::Base) -> Self{
        AirdropBuilder {
            params,
            spend_anchor: anchor,
            target_height,
            value_balance: Fr::random(0),
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
        let spend_description = sapling::bundle::SpendDescription::from_parts(
            cv: ValueCommitment,
            anchor: bls12_381::Scalar,
            nullifier: Nullifier,
            rk: redjubjub::VerificationKey<SpendAuth>,
            zkproof: A::SpendProof,
            spend_auth_sig: A::AuthSig,
        );
        self.spends.push(spend_description);
        self.value_balance += cv.as_inner().double().double().double();
        Ok(())
    }

    pub fn add_output<R: RngCore+ rand_core::CryptoRng>(
        &mut self,
        mut rng: R,
        ovk: Option<OutgoingViewingKey>,
        to: PaymentAddress,
        asset_type: AssetType,
        value: u64,
        memo: MemoBytes,
    ) -> Result<(), Error> {
        let g_d = to.g_d().ok_or(Error::InvalidAddress)?;
        if value > MAX_MONEY {
            return Err(Error::InvalidAmount);
        }
        let rseed = generate_random_rseed(&self.params, self.target_height, &mut rng);

        let note = Note {
            g_d,
            pk_d: *to.pk_d(),
            value,
            rseed,
            asset_type,
        };
        let output = SaplingOutputInfo::new(ovk, to, note, memo);
        self.value_balance -=
            ValueSum::from_pair(asset_type, value.into()).map_err(|_| Error::InvalidAmount)?;

        self.outputs.push(output);
        Ok(())
    }

    pub fn add_convert(
        &mut self,
        allowed: AllowedConversion,
        value: u64,
        merkle_path: MerklePath<Node>,
    ) -> Result<(), Error> {
        // Consistency check: all anchors must equal the first one

        let node = allowed.commitment();
        if let Some(anchor) = self.convert_anchor {
            let path_root: bls12_381::Scalar = merkle_path.root(node).into();
            if path_root != anchor {
                return Err(Error::AnchorMismatch);
            }
        } else {
            self.convert_anchor = Some(merkle_path.root(node).into())
        }

        let allowed_amt: I128Sum = allowed.clone().into();
        self.value_balance += I128Sum::from_sum(allowed_amt) * (value as i128);

        self.converts.push(ConvertDescriptionInfo::new(
            allowed,
            value,
            merkle_path,
        ));

        Ok(())
    }

    pub fn build<Pr: TxProver, R: RngCore>(
        self,
        prover: &Pr,
        ctx: &mut Pr::SaplingProvingContext,
        mut rng: R,
        target_height: BlockHeight,
        progress_notifier: Option<&Sender<Progress>>,
    ) {
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

        // Keep track of the total number of steps computed
        let total_progress = indexed_spends.len() as u32 + indexed_outputs.len() as u32;
        let mut progress = 0u32;

        // Create Sapling ConvertDescriptions
        let shielded_converts: Vec<ConvertDescription<GrothProofBytes>> =
            if !indexed_converts.is_empty() {
                let anchor = self
                    .convert_anchor
                    .expect("MASP convert_anchor must be set if MASP converts are present.");

                indexed_converts
                    .into_iter()
                    .enumerate()
                    .map(|(i, (pos, convert))| {
                        let (zkproof, cv) = prover
                            .convert_proof(
                                ctx,
                                convert.allowed.clone(),
                                convert.value,
                                anchor,
                                convert.merkle_path,
                            )
                            .map_err(|_| Error::ConvertProof)?;

                        // Record the post-randomized spend location
                        tx_metadata.convert_indices[pos] = i;

                        // Update progress and send a notification on the channel
                        progress += 1;
                        if let Some(sender) = progress_notifier {
                            // If the send fails, we should ignore the error, not crash.
                            sender
                                .send(Progress::new(progress, Some(total_progress)))
                                .unwrap_or(());
                        }

                        Ok(ConvertDescription {
                            cv,
                            anchor,
                            zkproof,
                        })
                    })
                    .collect::<Result<Vec<_>, Error>>()?
            } else {
                vec![]
            };
        // Create Sapling OutputDescriptions
        let shielded_outputs: Vec<OutputDescription<GrothProofBytes>> = indexed_outputs
            .into_iter()
            .enumerate()
            .map(|(i, output)| {
                let result = if let Some((pos, output)) = output {
                    // Record the post-randomized output location
                    tx_metadata.output_indices[pos] = i;

                    output.clone().build::<P, _, _>(prover, ctx, &mut rng)
                } else {
                    // This is a dummy output
                    let (dummy_to, dummy_note) = {
                        let (diversifier, g_d) = {
                            let mut diversifier;
                            let g_d;
                            loop {
                                let mut d = [0; 11];
                                rng.fill_bytes(&mut d);
                                diversifier = Diversifier(d);
                                if let Some(val) = diversifier.g_d() {
                                    g_d = val;
                                    break;
                                }
                            }
                            (diversifier, g_d)
                        };
                        let (pk_d, payment_address) = loop {
                            let dummy_ivk = jubjub::Fr::random(&mut rng);
                            let pk_d = g_d * dummy_ivk;
                            if let Some(addr) = PaymentAddress::from_parts(diversifier, pk_d) {
                                break (pk_d, addr);
                            }
                        };

                        let rseed =
                            generate_random_rseed_internal(&params, target_height, &mut rng);

                        (
                            payment_address,
                            Note {
                                g_d,
                                pk_d,
                                rseed,
                                value: 0,
                                asset_type: AssetType::new(b"dummy").unwrap(),
                            },
                        )
                    };

                    let esk = dummy_note.generate_or_derive_esk_internal(&mut rng);
                    let epk = dummy_note.g_d * esk;

                    let (zkproof, cv) = prover.output_proof(
                        ctx,
                        esk,
                        dummy_to,
                        dummy_note.rcm(),
                        dummy_note.asset_type,
                        dummy_note.value,
                    );

                    let cmu = dummy_note.cmu();

                    let mut enc_ciphertext = [0u8; 580 + 32];
                    let mut out_ciphertext = [0u8; 80];
                    rng.fill_bytes(&mut enc_ciphertext[..]);
                    rng.fill_bytes(&mut out_ciphertext[..]);

                    OutputDescription {
                        cv,
                        cmu,
                        ephemeral_key: epk.to_bytes().into(),
                        enc_ciphertext,
                        out_ciphertext,
                        zkproof,
                    }
                };

                // Update progress and send a notification on the channel
                progress += 1;
                if let Some(sender) = progress_notifier {
                    // If the send fails, we should ignore the error, not crash.
                    sender
                        .send(Progress::new(progress, Some(total_progress)))
                        .unwrap_or(());
                }

                result
            })
            .collect();

        let bundle = if shielded_spends.is_empty() && shielded_outputs.is_empty() {
            None
        } else {
            Some(Bundle {
                shielded_spends,
                shielded_converts,
                shielded_outputs,
                value_balance,
                authorization: Unauthorized { tx_metadata },
            })
        };

        Ok(bundle)
    }
}