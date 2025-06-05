pragma circom 2.1.9;

include "../utils/aadhaar/disclose/verify_commitment.circom";


template VC_AND_DISCLOSE_Aadhaar(nLevels){
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

    signal input merkle_root;
    signal input leaf_depth;
    signal input path[nLevels];
    signal input siblings[nLevels];

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
}

component main = VC_AND_DISCLOSE_Aadhaar(33);
