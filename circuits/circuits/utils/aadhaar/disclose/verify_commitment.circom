pragma circom 2.1.9;

include "@openpassport/zk-email-circuits/utils/bytes.circom";
include "@zk-kit/binary-merkle-root.circom/src/binary-merkle-root.circom";
include "../../passport/customHashers.circom";
include "../extractQrData.circom";

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
    signal input yob[4];
    signal input mob[2];
    signal input dob[2];
    signal input name[nameMaxLength()];
    signal input aadhaar_last_4digits[4];
    signal input pincode[6];
    signal input state[maxFieldByteSize()];
    signal input ph_no_last_4digits[4];
    signal input photoHash;

    signal input merkle_root;
    signal input merkletree_size;
    signal input path[nLevels];
    signal input siblings[nLevels];


    component commitmentHasher = CustomHasher(120);
    commitmentHasher.in[0] <== attestation_id;
    commitmentHasher.in[1] <== secret;
    commitmentHasher.in[2] <== qrDataHash;
    commitmentHasher.in[3] <== gender;

    for (var i = 0; i < 4 ; i++){
        commitmentHasher.in[i + 4] <== yob[i];
    }

    for (var i = 0; i < 2 ; i++){
        commitmentHasher.in[i + 8] <== mob[i];
    }

    for (var i = 0; i < 2 ; i++){
        commitmentHasher.in[i + 10] <== dob[i];
    }

    for (var i = 0; i < 62 ; i++){
        commitmentHasher.in[i + 12] <== name[i];
    }

    for (var i = 0; i < 4 ; i++){
        commitmentHasher.in[i + 74] <== aadhaar_last_4digits[i];
    }

    for (var i = 0; i < 6 ; i++){
        commitmentHasher.in[i + 78] <== pincode[i];
    }

    for (var i = 0; i < maxFieldByteSize() ; i++){
        commitmentHasher.in[i + 84] <== state[i];
    }

    for (var i = 0; i < 4 ; i++){
        commitmentHasher.in[i + 115] <== ph_no_last_4digits[i];
    }

    commitmentHasher.in[119] <== photoHash;

    signal commitment <== commitmentHasher.out;

    // Verify commitment inclusion
    signal computedRoot <== BinaryMerkleRoot(nLevels)(commitment, merkletree_size, path, siblings);
    merkle_root === computedRoot;

}
