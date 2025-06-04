pragma circom 2.1.9;

template VC_AND_DISCLOSE_Aadhaar(nLevels){
    signal input secret;
    signal input attestation_id;

    signal input merkle_root;
    signal input leaf_depth;
    signal input path[nLevels];
    signal input siblings[nLevels];

}
