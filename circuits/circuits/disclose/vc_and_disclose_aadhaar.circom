pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "../utils/aadhaar/disclose/verify_commitment.circom";
include "@openpassport/zk-email-circuits/utils/bytes.circom";
include "../utils/aadhaar/extractQrData.circom";
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
    signal input yob[4];
    signal input mob[2];
    signal input dob[2];
    signal input name[nameMaxLength()];
    signal input aadhaar_last_4digits[4];
    signal input pincode[6];
    signal input state[maxFieldByteSize()];
    signal input ph_no_last_4digits[4];
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
    // convert selector to 119 bits which acts as a bitmap for the fields to reveal
    signal sel_bits[119] <== Num2Bits(119)(selector);


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


    signal name_packed[2] <== PackBytes(nameMaxLength())(name);
    signal yob_integer <== DigitBytesToInt(4)(yob);
    signal mob_integer <== DigitBytesToInt(2)(mob);
    signal dob_integer <== DigitBytesToInt(2)(dob);

    // verify name-DOB in OFAC list
    component ofac_name_dob = OFAC_NAME_DOB_AADHAAR(namedobTreeLevels);
    ofac_name_dob.name <== name_packed;
    ofac_name_dob.YOB <== yob_integer;
    ofac_name_dob.MOB <== mob_integer;
    ofac_name_dob.DOB <== dob_integer;
    ofac_name_dob.smt_leaf_key <== ofac_name_dob_smt_leaf_key;
    ofac_name_dob.smt_root <== ofac_name_dob_smt_root;
    ofac_name_dob.smt_siblings <== ofac_name_dob_smt_siblings;

    // verify name-YOB in OFAC list
    component ofac_name_yob = OFAC_NAME_YOB_AADHAAR(nameyobTreeLevels);
    ofac_name_yob.name <== name_packed;
    ofac_name_yob.YOB <== yob_integer;
    ofac_name_yob.smt_leaf_key <== ofac_name_yob_smt_leaf_key;
    ofac_name_yob.smt_root <== ofac_name_yob_smt_root;
    ofac_name_yob.smt_siblings <== ofac_name_yob_smt_siblings;

    // reveal fields based on selector
    signal output reveal_gender <== gender * sel_bits[0];

    signal output reveal_yob[4];
    signal yob_int[4];
    for (var i = 0; i < 4; i++){
        yob_int[i] <== DigitBytesToInt(1)([yob[i]]);
        reveal_yob[i] <== yob_int[i] * sel_bits[i + 1];
    }

    signal output reveal_mob[2];
    signal mob_int[2];
    for (var i = 0; i < 2; i++){
        mob_int[i] <== DigitBytesToInt(1)([mob[i]]);
        reveal_mob[i] <== mob_int[i] * sel_bits[i + 5];
    }

    signal output reveal_dob[2];
    signal dob_int[2];
    for (var i = 0; i < 2; i++){
        dob_int[i] <== DigitBytesToInt(1)([dob[i]]);
        reveal_dob[i] <== dob_int[i] * sel_bits[i + 7];
    }

    signal output reveal_name[nameMaxLength()];
    for (var i = 0; i < nameMaxLength(); i++){
        reveal_name[i] <== name[i] * sel_bits[i + 9];
    }

    signal output reveal_aadhaar_last_4digits[4];
    signal aadhaar_last_4digits_int[4];
    for (var i = 0; i < 4; i++){
        aadhaar_last_4digits_int[i] <== DigitBytesToInt(1)([aadhaar_last_4digits[i]]);
        reveal_aadhaar_last_4digits[i] <== aadhaar_last_4digits_int[i] * sel_bits[i + 71];
    }

    signal output reveal_pincode[6];
    signal pincode_int[6];
    for (var i = 0; i < 6; i++){
        pincode_int[i] <== DigitBytesToInt(1)([pincode[i]]);
        reveal_pincode[i] <== pincode_int[i] * sel_bits[i + 75];
    }

    signal output reveal_state[maxFieldByteSize()];
    for (var i = 0; i < maxFieldByteSize(); i++){
        reveal_state[i] <== state[i] * sel_bits[i + 81];
    }

    signal output reveal_ph_no_last_4digits[4];
    signal ph_no_last_4digits_int[4];
    for (var i = 0; i < 4; i++){
        ph_no_last_4digits_int[i] <== DigitBytesToInt(1)([ph_no_last_4digits[i]]);
        reveal_ph_no_last_4digits[i] <== ph_no_last_4digits_int[i] * sel_bits[i + 112];
    }

    signal output reveal_photoHash <== photoHash * sel_bits[116];

    signal output reveal_ofac_name_dob <== ofac_name_dob.ofacCheckResult * sel_bits[117];
    signal output reveal_ofac_name_yob <== ofac_name_yob.ofacCheckResult * sel_bits[118];

}

component main { public
    [
        merkle_root,
        ofac_name_dob_smt_root,
        ofac_name_yob_smt_root,
        attestation_id
    ]
} = VC_AND_DISCLOSE_Aadhaar(33, 64, 64);
