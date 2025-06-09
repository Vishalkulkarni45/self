pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "../utils/aadhaar/disclose/verify_commitment.circom";
include "../utils/aadhaar/ofac/ofac_name_dob.circom";
include "../utils/aadhaar/ofac/ofac_name_yob.circom";

/// @title VC_AND_DISCLOSE_Aadhaar
/// @notice Verify user's commitment is part of the merkle tree and optionally disclose data from Aadhaar
/// @param nLevels Maximum number of levels in the merkle tree
/// @param namedobTreeLevels Maximum number of levels in the name-dob SMT tree
/// @param nameyobTreeLevels Maximum number of levels in the name-yob SMT tree
/// @input attestation_id Attestation ID of the credential used to generate the commitment
/// @input secret Secret of the user — used to reconstruct commitment
/// @input qrDataHash Hash of the QR data
/// @input gender Gender of the user
/// @input yob Year of birth
/// @input mob Month of birth
/// @input dob Day of birth
/// @input name[2] Name of the user (packed into 2 field elements)
/// @input aadhaar_last_4digits Last 4 digits of Aadhaar number
/// @input pincode Pincode of user's address
/// @input state State(PackedBytes) of user's address
/// @input ph_no_last_4digits Last 4 digits of phone number
/// @input photoHash Hash of user's photo
/// @input ofac_name_dob_smt_leaf_key Leaf key for name-DOB SMT verification
/// @input ofac_name_dob_smt_root Root of name-DOB SMT
/// @input ofac_name_dob_smt_siblings Siblings for name-DOB SMT proof
/// @input ofac_name_yob_smt_leaf_key Leaf key for name-YOB SMT verification
/// @input ofac_name_yob_smt_root Root of name-YOB SMT
/// @input ofac_name_yob_smt_siblings Siblings for name-YOB SMT proof
/// @input merkle_root Root of the commitment merkle tree
/// @input leaf_depth Actual size of the merkle tree
/// @input path Path of the commitment in the merkle tree
/// @input siblings Siblings of the commitment in the merkle tree
/// @input selector Bitmap indicating which fields to reveal
template VC_AND_DISCLOSE_Aadhaar(nLevels, namedobTreeLevels, nameyobTreeLevels){
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


    signal input ofac_name_dob_smt_leaf_key;
    signal input ofac_name_dob_smt_root;
    signal input ofac_name_dob_smt_siblings[namedobTreeLevels];

    signal input ofac_name_yob_smt_leaf_key;
    signal input ofac_name_yob_smt_root;
    signal input ofac_name_yob_smt_siblings[nameyobTreeLevels];


    signal input merkle_root;
    signal input leaf_depth;
    signal input path[nLevels];
    signal input siblings[nLevels];

    signal input selector;
    // convert selector to 12 bits which acts as a bitmap for the fields to reveal
    signal sel_bits[12] <== Num2Bits(12)(selector);


    // verify commitment is part of the merkle tree
    VERIFY_COMMITMENT(nLevels)(
        attestation_id,
        secret,
        qrDataHash,
        gender,
        yob,
        mob,
        dob,
        name,
        aadhaar_last_4digits,
        pincode,
        state,
        ph_no_last_4digits,
        photoHash,
        merkle_root,
        leaf_depth,
        path,
        siblings
    );

    // verify name-DOB in OFAC list
    component ofac_name_dob = OFAC_NAME_DOB_AADHAAR(namedobTreeLevels);
    ofac_name_dob.name <== name;
    ofac_name_dob.YOB <== yob;
    ofac_name_dob.MOB <== mob;
    ofac_name_dob.DOB <== dob;
    ofac_name_dob.smt_leaf_key <== ofac_name_dob_smt_leaf_key;
    ofac_name_dob.smt_root <== ofac_name_dob_smt_root;
    ofac_name_dob.smt_siblings <== ofac_name_dob_smt_siblings;

    // verify name-YOB in OFAC list
    component ofac_name_yob = OFAC_NAME_YOB_AADHAAR(nameyobTreeLevels);
    ofac_name_yob.name <== name;
    ofac_name_yob.YOB <== yob;
    ofac_name_yob.smt_leaf_key <== ofac_name_yob_smt_leaf_key;
    ofac_name_yob.smt_root <== ofac_name_yob_smt_root;
    ofac_name_yob.smt_siblings <== ofac_name_yob_smt_siblings;

    // reveal fields based on selector
    signal output reveal_gender <== gender * sel_bits[0];
    signal output reveal_yob <== yob * sel_bits[1];
    signal output reveal_mob <== mob * sel_bits[2];
    signal output reveal_dob <== dob * sel_bits[3];
    signal output reveal_name[2];
    reveal_name[0] <== name[0] * sel_bits[4];
    reveal_name[1] <== name[1] * sel_bits[4];
    signal output reveal_aadhaar_last_4digits <== aadhaar_last_4digits * sel_bits[5];
    signal output reveal_pincode <== pincode * sel_bits[6];
    signal output reveal_state <== state * sel_bits[7];
    signal output reveal_ph_no_last_4digits <== ph_no_last_4digits * sel_bits[8];
    signal output reveal_photoHash <== photoHash * sel_bits[9];
    signal output reveal_ofac_name_dob <== ofac_name_dob.ofacCheckResult * sel_bits[10];
    signal output reveal_ofac_name_yob <== ofac_name_yob.ofacCheckResult * sel_bits[11];


}

component main { public
    [
        merkle_root,
        ofac_name_dob_smt_root,
        ofac_name_yob_smt_root,
        attestation_id
    ]
} = VC_AND_DISCLOSE_Aadhaar(33, 64, 64);
