pragma circom 2.1.9;
include "../register_aadhaar.circom";

component main { public [ pubKey ] }  = REGISTER_AADHAAR(121, 17, 512 * 3);
