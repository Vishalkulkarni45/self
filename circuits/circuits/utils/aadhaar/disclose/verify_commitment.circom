pragma circom 2.1.9;

include "@openpassport/zk-email-circuits/utils/bytes.circom";
include "@zk-kit/binary-merkle-root.circom/src/binary-merkle-root.circom";
include "../../passport/customHashers.circom";

/// @notice VerifyCommitment template — verifies user's commitment is included in the merkle tree
/// @param nLevels Maximum size of the merkle tree
/// @input secret Secret for commitment generation
/// @input attestation_id Attestation ID
/// @input merkle_root Root of the commitment merkle tree
/// @input merkletree_size Actual size of the merkle tree
/// @input path Path to the user's commitment in the merkle tree
/// @input siblings Siblings of the user's commitment in the merkle tree
template VERIFY_COMMITMENT(nLevels) {
    signal input attestation_id;
    signal input secret;
    signal input qrDataHash;
    signal input gender;
    signal input yob;
    signal input mob;
    signal input dob;
    signal input name[2];
    signal input aadhaar_last_4digits;
    signal input pincode;
    signal input state;
    signal input ph_no_last_4digits;
    signal input photoHash;

    signal input merkle_root;
    signal input merkletree_size;
    signal input path[nLevels];
    signal input siblings[nLevels];

    signal commitment <== Poseidon(14)([
        attestation_id,
        secret,
        qrDataHash,
        gender,
        yob,
        mob,
        dob,
        name[0],
        name[1],
        aadhaar_last_4digits,
        pincode,
        state,
        ph_no_last_4digits,
        photoHash
    ]);


    // Verify commitment inclusion
    signal computedRoot <== BinaryMerkleRoot(nLevels)(commitment, merkletree_size, path, siblings);
    merkle_root === computedRoot;

}
