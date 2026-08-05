//! Golden-bytes pins for the wire structs whose signature/key fields the
//! crypto seam touches. Any drift in the expected hex means a wire-format
//! break — deliberate re-pins accompany deliberate encoding changes.

use hex::encode as hex_encode;
use hyperscale_hbor::{HborEncode, to_vec as hbor_to_vec};
use hyperscale_types::{
    AggregateSignature, BlockHash, BlockHeight, BlockVote, ConsensusPublicKey, ConsensusSignature,
    Hash, PcCompactVote, PcQc1, PcValueElement, PcVector, PositionalBundle, ProposerTimestamp,
    QuorumCertificate, Round, ShardId, SignerBitfield, ValidatorId, ValidatorInfo,
    WeightedTimestamp,
};

fn assert_golden<T: HborEncode>(value: &T, expected_hex: &str, label: &str) {
    let actual = hex_encode(hbor_to_vec(value).unwrap());
    assert_eq!(
        actual, expected_hex,
        "{label}: encoding drifted from the golden bytes"
    );
}

fn golden_signers() -> SignerBitfield {
    let mut signers = SignerBitfield::new(4);
    signers.set(0);
    signers.set(2);
    signers
}

#[test]
fn quorum_certificate_golden_bytes() {
    let qc = QuorumCertificate::new(
        BlockHash::from_raw(Hash::from_bytes(b"golden-qc-block")),
        ShardId::leaf(2, 0b10),
        BlockHeight::new(42),
        BlockHash::from_raw(Hash::from_bytes(b"golden-qc-parent")),
        Round::new(3),
        golden_signers(),
        AggregateSignature::new([0x22; 96]),
        WeightedTimestamp::from_millis(1_700_000_000_123),
    );
    assert_golden(&qc, EXPECTED_QC, "QuorumCertificate");
}

#[test]
fn block_vote_golden_bytes() {
    let vote = BlockVote::from_parts(
        BlockHash::from_raw(Hash::from_bytes(b"golden-vote-block")),
        ShardId::leaf(1, 0b1),
        BlockHeight::new(7),
        Round::new(1),
        ValidatorId::new(5),
        ConsensusSignature::new([0x33; 96]),
        ProposerTimestamp::from_millis(1_700_000_000_456),
    );
    assert_golden(&vote, EXPECTED_BLOCK_VOTE, "BlockVote");
}

#[test]
fn validator_info_golden_bytes() {
    let info = ValidatorInfo {
        validator_id: ValidatorId::new(9),
        public_key: ConsensusPublicKey::new([0x44; 48]),
    };
    assert_golden(&info, EXPECTED_VALIDATOR_INFO, "ValidatorInfo");
}

#[test]
fn pc_qc1_golden_bytes() {
    let x = PcVector::new([
        PcValueElement::from_digest([0x55; 32], b"golden"),
        PcValueElement::from_digest([0x66; 32], b"golden"),
    ]);
    let x_signers = PositionalBundle::new(
        golden_signers(),
        vec![
            PcCompactVote::new(2, None),
            PcCompactVote::new(1, Some(PcValueElement::from_digest([0x77; 32], b"golden"))),
        ],
    );
    let qc1 = PcQc1::new(x, x_signers, AggregateSignature::new([0x88; 96]));
    assert_golden(&qc1, EXPECTED_PC_QC1, "PcQc1");
}

const EXPECTED_QC: &str = "e7c8d8fecb84404480148f65172ce95b9984e1ec56f84494e6ad90391dc36cd70200000002000000000000002a000000000000002356d22ed37a6538fc945a8e30ea532612029962653bf993560b365ae3fe594c0300000000000000010504002222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222227b68e5cf8b010000";
const EXPECTED_BLOCK_VOTE: &str = "b3e13454f2b0dab7471e3e5db927fd492e114b13595a462f5a4c066bd516783b010000000100000000000000070000000000000001000000000000000500000000000000333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333c869e5cf8b010000";
const EXPECTED_VALIDATOR_INFO: &str = "0900000000000000444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444444";
const EXPECTED_PC_QC1: &str = "02555555555555555555555555555555555555555555555555555555555555555566666666666666666666666666666666666666666666666666666666666666660105040002020000000001000000017777777777777777777777777777777777777777777777777777777777777777888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888888";
