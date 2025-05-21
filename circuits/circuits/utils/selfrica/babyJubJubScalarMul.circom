pragma circom 2.1.9;

include "../crypto/bigInt/bigInt.circom";
template BabyScalarMul(){
    signal input in1[4];
    signal input in2[4];

    signal output out[4];

    signal scalar_mod[4];
   //2736030358979909402780800718157159386076813972158567259200215660948447373041(SUBGROUP ORDER)
    scalar_mod[0] <== 7454187305358665457;
    scalar_mod[1] <== 12339561404529962506;
    scalar_mod[2] <== 3965992003123030795;
    scalar_mod[3] <== 435874783350371333;

    component mulmod = BigMultModP(64,4,4,4);
    
    for(var i = 0; i < 4; i++){
        mulmod.in1[i]<== in1[i];
        mulmod.in2[i]<== in2[i];
        mulmod.modulus[i]<== scalar_mod[i];
    }
    for(var i = 0; i < 4 ; i++){
        out[i] <== mulmod.mod[i];
    }

}