pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "../utils/aadhaar/disclose/verify_commitment.circom";
include "../utils/aadhaar/ofac/ofac_name_dob.circom";
include "../utils/aadhaar/ofac/ofac_name_yob.circom";

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

    signal sel_bits[11] <== Num2Bits(11)(selector);


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
        ph_no_last_4digits,
        photoHash,
        merkle_root,
        leaf_depth,
        path,
        siblings
    );

    component ofac_name_dob = OFAC_NAME_DOB_AADHAAR(namedobTreeLevels);
    ofac_name_dob.name <== name;
    ofac_name_dob.YOB <== yob;
    ofac_name_dob.MOB <== mob;
    ofac_name_dob.DOB <== dob;
    ofac_name_dob.smt_leaf_key <== ofac_name_dob_smt_leaf_key;
    ofac_name_dob.smt_root <== ofac_name_dob_smt_root;
    ofac_name_dob.smt_siblings <== ofac_name_dob_smt_siblings;

    component ofac_name_yob = OFAC_NAME_YOB_AADHAAR(nameyobTreeLevels);
    ofac_name_yob.name <== name;
    ofac_name_yob.YOB <== yob;
    ofac_name_yob.smt_leaf_key <== ofac_name_yob_smt_leaf_key;
    ofac_name_yob.smt_root <== ofac_name_yob_smt_root;
    ofac_name_yob.smt_siblings <== ofac_name_yob_smt_siblings;

    signal output reveal_gender <== gender * sel_bits[0];
    signal output reveal_yob <== yob * sel_bits[1];
    signal output reveal_mob <== mob * sel_bits[2];
    signal output reveal_dob <== dob * sel_bits[3];
    signal output reveal_name[2];
    reveal_name[0] <== name[0] * sel_bits[4];
    reveal_name[1] <== name[1] * sel_bits[4];
    signal output reveal_aadhaar_last_4digits <== aadhaar_last_4digits * sel_bits[5];
    signal output reveal_pincode <== pincode * sel_bits[6];
    signal output reveal_ph_no_last_4digits <== ph_no_last_4digits * sel_bits[7];
    signal output reveal_photoHash <== photoHash * sel_bits[8];
    signal output reveal_ofac_name_dob <== ofac_name_dob.ofacCheckResult * sel_bits[9];
    signal output reveal_ofac_name_yob <== ofac_name_yob.ofacCheckResult * sel_bits[10];


}

component main = VC_AND_DISCLOSE_Aadhaar(33, 64, 64);
