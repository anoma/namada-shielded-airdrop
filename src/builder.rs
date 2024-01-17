use core::fmt::Debug;
use std::iter;
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
use masp_primitives::transaction::components::I128Sum;
use masp_primitives::asset_type::AssetType;
use masp_primitives::keys::OutgoingViewingKey;
use masp_primitives::memo::MemoBytes;
use masp_primitives::sapling::PaymentAddress;
use masp_primitives::transaction::components::sapling::Bundle;
use rand::prelude::SliceRandom;
use sapling::{
    zip32::ExtendedSpendingKey,
    Diversifier,
    MerklePath as SapMerklePath,
    Note as SapNote,
    builder::{Error, SpendInfo},
    value::ValueSum as SapValueSum,
};
use rand_core::RngCore;
use sapling::bundle::SpendDescription;
use crate::builder;


pub(crate) const GROTH_PROOF_SIZE: usize = 48 + 96 + 48;
pub const MAX_MONEY: u64 = u64::MAX;


pub struct AirdropBuilder<P> {
    params: P,
    spend_anchor: jubjub::Base,
    target_height: BlockHeight,
    value_balance: I128Sum,
    convert_anchor: Option<bls12_381::Scalar>,
    spends: Vec<SpendInfo>,
    converts: Vec<ConvertDescriptionInfo>,
    outputs: Vec<SaplingOutputInfo>,
}

impl<P: consensus::Parameters> AirdropBuilder<P> {

    /// initialize the airdrop tool with the sapling spend commitment tree anchor
    pub fn init(params: P, target_height: BlockHeight, anchor: jubjub::Base) -> Self{
        AirdropBuilder {
            params,
            spend_anchor: anchor,
            target_height,
            value_balance: ValueSum::zero(),
            convert_anchor: None,
            spends: vec![],
            converts: vec![],
            outputs: vec![],
        }
    }
    pub fn add_spend<R: RngCore>(
        &mut self,
        extsk: ExtendedSpendingKey,
        note: SapNote,
        merkle_path: SapMerklePath,
    )-> Result<(), Error> {
        let spend = SpendInfo::new(extsk.expsk.proof_generation_key(), note, merkle_path);
        let sap_asset_type = AssetType::new(b"SapAir").unwrap();
        let note_value = ValueSum::from_pair(sap_asset_type, spend.value().inner().into()).unwrap();
        self.value_balance += note_value;
        self.spends.push(spend);
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
}