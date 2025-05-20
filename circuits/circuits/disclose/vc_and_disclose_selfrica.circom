pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/compconstant.circom"
include "circomlib/circuits/comparators.circom"
include "../utils/selfrica/babyJubJubScalarMul.circom";
include "../utils/passport/customHashers.circom";
include "../utils/selfrica/babyEcdsa.circom";
include "@openpassport/zk-email-circuits/lib/bigint.circom";

template VC_AND_DISCLOSE(n) {
    
    signal input SmileID_data[n];
    //signal input disclose_sel[n];
    signal input s;
    signal input Tx; 
    signal input Ty; 
    signal input r_inv;
    signal input Ux;
    signal input Uy;
    signal input pubKeyX;
    signal input pubKeyY;

    //Supply -r_inv
    signal input r_inv[4];

    // signal output pi_hash;
    // signal reveal_data[n];

   

    var SUBGROUP_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    var BASE8[2] = [
            5299619240641551281634865583518297030282874472190772894086521144482721001553,
            16950150798460657717958625567821834550301663161624707787222815936182638968203
        ];

    signal computedNum2Bits[254] = Num2Bits(254)(s);
    signal computedCompConstantIn[254] = computedNum2Bits;
    // computedCompConstantIn[253] === 0;
    // computedCompConstantIn[252] === 0;
    // computedCompConstantIn[254] === 0;

    signal computedCompConstant = CompConstant(SUBGROUP_ORDER - 1)(computedCompConstantIn);
    computedCompConstant.out === 0;


    signal scalar_mod[4];
   // SUBGROUP ORDER in limbs
    scalar_mod[0] <== 7454187305358665457;
    scalar_mod[1] <== 12339561404529962506;
    scalar_mod[2] <== 3965992003123030795;
    scalar_mod[3] <== 435874783350371333;

    
    //TODO: check BigLessThan bez it passes even if r_inv = scalar_mod
    //Check is - r_inv < scalar_mod
    component scalar_range_check = BigLessThan(64,4);
    scalar_range_check.a <== r_inv;
    scalar_range_check.b <== scalar_mod;
    scalar_range_check.out === 1 ;

    //Calculate msg_hash
    component msg_hasher = calSmileDataHash()(SmileID_data);

    component bit_decompose = Num2Bits(256);
    bit_decompose.in <== msg_hasher.out;
    signal msg_hash_bits[256] <== bit_decompose.out;


    signal msg_hash_limbs[4];
    component bits2Num[4];

    //convert msg_hash to 4 limbs
    for (var i = 0; i < 4; i++) {
        bits2Num[i] = Bits2Num(64);
        for (var j = 0; j < 64; j++) {
            bits2Num[i].in[64 - 1 - j] <== msg_hash_bits[i * 64 + j];
        }
        msg_hash_limbs[4 - 1 - i] <== bits2Num[i].out;
    }

    // calculates (-r_inv * msg_hash) % SUBGROUP_ORDER
    component r_inv_msg_hash = BabyScalarMul();
    for(var i =0 ;i<4 ;i++){
        mul_scalar.in1[i] <== r_inv[i];
        mul_scalar.in2[i] <== msg_hash_limbs[i];
    }

    signal r_inv_msg_hash_bits[256];
    component num2bits[4];

    //convert r_inv_msg_hash limbs to bits
    for (var i=0; i<4; i++){
        num2bits[i]= Num2Bits(64);
        num2bits[i].in <==r_inv_msg_hash.out[i];
        for(var j=0; j<64; j++){
            r_inv_msg_hash_bits[i*64+j] <== num2bits[i].out[j];
        }
    }

    component mulFix = EscalarMulFix(256, BASE8);
    for (i=0; i<256; i++) {
        mulFix.e[i] <== r_inv_msg_hash_bits[i];
    }

    component ecdsa = BabyJubJubECDSA();
    ecdsa.Tx <== Tx;
    ecdsa.Ty <== Ty;
    ecdsa.Ux <== mulFix.out[0];
    ecdsa.Uy <== mulFix.out[1];
    ecdsa.s <== s;

    ecdsa.pubKeyX === pubKeyX;
    ecdsa.pubKeyY === pubKeyY;

    signal is_pkx_zero = IsZero()(publicKeyX);
    is_pkx_zero === 0;

  }

template calSmileDataHash(){
    signal input data[298];
    signal output out;

    component hasher16[19];
    signal inter_hash_1_16[18];

    for (var i = 0; i<18 ; i++){
        hasher16[i] = Poseidon(16);
        for (var j = 0; j<16 ; j++){
            hasher16[i].in[j] <== data[i*16+j];
        }
        inter_hash_1_16[i] <== hasher16[i].out;
    }
   
    hasher16[18] = Poseidon(16);
    for (var i = 0; i<16 ; i++){
        hasher16[18].in[i] <== inter_hash_1_16[i];
    }

    component hasher12 = Poseidon(12);
    hasher12.in[0] <== inter_hash_1_16[16];
    hasher12.in[1] <== inter_hash_1_16[17];

    for(var i = 18 * 16; i<298 ; i++){
        hasher12.in[i - 18 * 16 + 2] <== data[i];
    }

    component hasher = Poseidon(2);
    hasher.in[0] <== hasher16[18].out;
    hasher.in[1] <== hasher12.out;

    out <== hasher.out;

}
