pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/escalarmulfix.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/compconstant.circom";
include "circomlib/circuits/comparators.circom";
include "../utils/selfrica/babyJubJubScalarMul.circom";
include "../utils/passport/customHashers.circom";
include "../utils/selfrica/babyEcdsa.circom";
include "@openpassport/zk-email-circuits/lib/bigint.circom";

template VC_AND_DISCLOSE() {
    
    signal input SmileID_data[298];
    signal input disclose_sel[298];
    signal input s;
    signal input Tx; 
    signal input Ty; 
    signal input pubKeyX;
    signal input pubKeyY;

    //Supply -r_inv
    signal input r_inv[4];

    signal output pi_hash;

    component ascii_range_check[298];
    component pi_hasher = CustomHasher298();
    for(var i=0; i<298; i++){
        // Check if the data is in the ASCII range 0 - 127
        ascii_range_check[i] = Num2Bits(7); 
        ascii_range_check[i].in <== SmileID_data[i];

        //Check is selctor binary
        disclose_sel[i] * (disclose_sel[i] - 1) === 0;
        pi_hasher.in[i] <== disclose_sel[i] * SmileID_data[i];
    }

    pi_hash <== pi_hasher.out;


   
    var SUBGROUP_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    var BASE8[2] = [
            5299619240641551281634865583518297030282874472190772894086521144482721001553,
            16950150798460657717958625567821834550301663161624707787222815936182638968203
        ];

    component computNum2Bits = Num2Bits(254);
    computNum2Bits.in <== s;
    signal computedCompConstantIn[254] <== computNum2Bits.out;
    computedCompConstantIn[252] === 0;
    computedCompConstantIn[253] === 0;

    component computedCompConstant = CompConstant(SUBGROUP_ORDER - 1);
    computedCompConstant.in <== computedCompConstantIn;
    computedCompConstant.out === 0;

    // Check if s is not 0
    signal is_s_zero <== IsZero()(s);
    is_s_zero === 0;

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
    component msg_hasher = CustomHasher298();
    for (var i = 0; i < 298; i++) {
        msg_hasher.in[i] <== SmileID_data[i];
    }

    component bit_decompose = Num2Bits(256);
    bit_decompose.in <== msg_hasher.out;
    signal msg_hash_bits[256] <== bit_decompose.out;


    signal msg_hash_limbs[4];
    component bits2Num[4];

    // Convert msg_hash_bits (little-endian) to 4 LE limbs
    for (var i = 0; i < 4; i++) {
        bits2Num[i] = Bits2Num(64);
        for (var j = 0; j < 64; j++) {
            bits2Num[i].in[j] <== msg_hash_bits[i * 64 + j];
        }
        msg_hash_limbs[i] <== bits2Num[i].out;
    }

    // calculates (-r_inv * msg_hash) % SUBGROUP_ORDER
    component r_inv_msg_hash = BabyScalarMul();
    for(var i =0 ;i<4 ;i++){
        r_inv_msg_hash.in1[i] <== r_inv[i];
        r_inv_msg_hash.in2[i] <== msg_hash_limbs[i];
    }

    signal r_inv_msg_hash_bits[256];
    component num2bits[4];

   // convert r_inv_msg_hash limbs to bits
    for (var i=0; i<4; i++){
        num2bits[i]= Num2Bits(64);
        num2bits[i].in <==r_inv_msg_hash.out[i];
        for(var j=0; j<64; j++){
            r_inv_msg_hash_bits[i*64+j] <== num2bits[i].out[j];
        }
    }
    r_inv_msg_hash_bits[255] === 0;
    r_inv_msg_hash_bits[254] === 0;


    component mulFix = EscalarMulFix(254, BASE8);
    for (var i=0; i<254; i++) {
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

    signal is_pkx_zero <== IsZero()(pubKeyX);
    is_pkx_zero === 0;

  }


template CustomHasher298(){
    signal input in[298];
    signal output out;

    var FULL_CHUNK_SIZE = 16;
    var FULL_CHUNK_COUNT = 18;
    var REMAINING_DATA = 298 - FULL_CHUNK_SIZE * FULL_CHUNK_COUNT;  // 10

    // Step 1: Hash each 16-element chunk
    component hasher16[FULL_CHUNK_COUNT];
    signal inter_hash_1_16[FULL_CHUNK_COUNT];

    for (var i = 0; i < FULL_CHUNK_COUNT; i++) {
        hasher16[i] = Poseidon(FULL_CHUNK_SIZE);
        for (var j = 0; j < FULL_CHUNK_SIZE; j++) {
            hasher16[i].inputs[j] <== in[i * FULL_CHUNK_SIZE + j];
        }
        inter_hash_1_16[i] <== hasher16[i].out;
    }

    // Step 2: Hash first 16 intermediate hashes → h_2_16
    component hasher2_16 = Poseidon(FULL_CHUNK_SIZE);
    for (var i = 0; i < FULL_CHUNK_SIZE; i++) {
        hasher2_16.inputs[i] <== inter_hash_1_16[i];
    }

    // Step 3: Hash [last 2 intermediate hashes + remaining 10 data values] → h_2_12
    component hasher2_12 = Poseidon(12);
    hasher2_12.inputs[0] <== inter_hash_1_16[16];
    hasher2_12.inputs[1] <== inter_hash_1_16[17];

    for (var i = 0; i < REMAINING_DATA; i++) {
        hasher2_12.inputs[i + 2] <== in[FULL_CHUNK_SIZE * FULL_CHUNK_COUNT + i]; // data[288 + i]
    }

    // Fill any remaining Poseidon(12) inputs with 0
    for (var i = REMAINING_DATA + 2; i < 12; i++) {
        hasher2_12.inputs[i] <== 0;
    }

    // Step 4: Final hash
    component finalHasher = Poseidon(2);
    finalHasher.inputs[0] <== hasher2_16.out;
    finalHasher.inputs[1] <== hasher2_12.out;

    out <== finalHasher.out;
}