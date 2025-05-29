pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "../utils/selfrica/verifySignature.circom";
include "../utils/passport/customHashers.circom";
include "../utils/selfrica/babyEcdsa.circom";
include "@openpassport/zk-email-circuits/lib/bigint.circom";
include "../utils/selfrica/constants.circom";
include "../utils/selfrica/disclose/disclose.circom";

template VC_AND_DISCLOSE(
    MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH, 
    namedobTreeLevels,
    nameyobTreeLevels
) {
    var selfrica_length = SELFRICA_MAX_LENGTH();
    var country_length = COUNTRY_LENGTH();

    signal input SmileID_data[selfrica_length];
    signal input disclose_sel[selfrica_length];
    //Args to verify Hash(smiledata) signature
    signal input s;
    signal input Tx; 
    signal input Ty; 
    signal input pubKeyX;
    signal input pubKeyY;

    //Args to verify Hash(IdNumber) signature
    signal input nullifier_s;
    signal input nullifier_Tx; 
    signal input nullifier_Ty; 
    signal input nullifier_Ux; 
    signal input nullifier_Uy; 
    signal input scope;


    signal input forbidden_countries_list[MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH * country_length];

    signal input ofac_name_dob_smt_leaf_key;
    signal input ofac_name_dob_smt_root;
    signal input ofac_name_dob_smt_siblings[namedobTreeLevels];

    signal input ofac_name_yob_smt_leaf_key;
    signal input ofac_name_yob_smt_root;
    signal input ofac_name_yob_smt_siblings[nameyobTreeLevels];

    signal input selector_ofac;
    signal input attestation_id;

    //Supply -r_inv for identity commitment sig verification
    signal input r_inv[4];
    //Supply -r_inv for nullifier sig verification
    signal input r_inv_nullifier[4];

    component ascii_range_check[selfrica_length];

    for(var i = 0; i < selfrica_length; i++){
        // Check if the data is in the ASCII range 0 - 127
        ascii_range_check[i] = Num2Bits(7); 
        ascii_range_check[i].in <== SmileID_data[i];

        //Check is selctor binary
        disclose_sel[i] * (disclose_sel[i] - 1) === 0;
    }

    //Calculate msg_hash
    component msg_hasher = PackBytesAndPoseidon(selfrica_length);
    for (var i = 0; i < selfrica_length; i++) {
        msg_hasher.in[i] <== SmileID_data[i];
    }

    //msg_hash bit decomposition
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

    //verify Hash(smiledata) signature
    component verifyIdCommSig = VERIFY_ECDSA_SIGNATURE();
    verifyIdCommSig.s <== s;
    verifyIdCommSig.r_inv <== r_inv;
    verifyIdCommSig.msg_hash_limbs <== msg_hash_limbs;
    verifyIdCommSig.Tx <== Tx;
    verifyIdCommSig.Ty <== Ty; 
    verifyIdCommSig.pubKeyX <== pubKeyX;
    verifyIdCommSig.pubKeyY <== pubKeyY;

    //Calculate IDNUMBER hash
    component id_num_hasher = PackBytesAndPoseidon(ID_NUMBER_LENGTH());
    var idNumberIdx = ID_NUMBER_INDEX();
    for (var i = 0; i < ID_NUMBER_LENGTH(); i++) {
        id_num_hasher.in[i] <== SmileID_data[idNumberIdx +  i];
    }

    //id_num_hash bit decomposition
    component id_hash_bit_decompose = Num2Bits(256);
    id_hash_bit_decompose.in <== id_num_hasher.out;
    signal id_num_hash_bits[256] <== id_hash_bit_decompose.out;


    signal id_num_hash_limbs[4];
    component id_num_bits2Num[4];

    // Convert id_num_hash_bits (little-endian) to 4 LE limbs
    for (var i = 0; i < 4; i++) {
        id_num_bits2Num[i] = Bits2Num(64);
        for (var j = 0; j < 64; j++) {
            id_num_bits2Num[i].in[j] <== id_num_hash_bits[i * 64 + j];
        }
        id_num_hash_limbs[i] <== id_num_bits2Num[i].out;
    }

    //verify Hash(IdNumber) signature
    component verifyNullifierSig = VERIFY_ECDSA_SIGNATURE();
    verifyNullifierSig.s <== nullifier_s;
    verifyNullifierSig.r_inv <== r_inv_nullifier;
    verifyNullifierSig.msg_hash_limbs <== id_num_hash_limbs;
    verifyNullifierSig.Tx <== nullifier_Tx;
    verifyNullifierSig.Ty <== nullifier_Ty; 
    verifyNullifierSig.pubKeyX <== pubKeyX;
    verifyNullifierSig.pubKeyY <== pubKeyY;

 
    // Identity Commitment = Hash( IdNumCommit sig )
    component idCommCal = Poseidon(1);
    idCommCal.inputs[0] <== s;
    signal output identity_commitment <== idCommCal.out;

    //Nullifier = HASH( nullifier sig , scope )
    component nullifierCal = Poseidon(2);
    nullifierCal.inputs[0] <== nullifier_s;
    nullifierCal.inputs[1] <== scope;
    signal output nullifier <== nullifierCal.out;


    component disclose_circuit = DISCLOSE_SELFRICA(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH, namedobTreeLevels, nameyobTreeLevels);

    disclose_circuit.smile_data <== SmileID_data;
    disclose_circuit.selector_smile_data <== disclose_sel;
    disclose_circuit.forbidden_countries_list <== forbidden_countries_list;

    disclose_circuit.ofac_name_dob_smt_leaf_key <== ofac_name_dob_smt_leaf_key;
    disclose_circuit.ofac_name_dob_smt_root <== ofac_name_dob_smt_root;
    disclose_circuit.ofac_name_dob_smt_siblings <== ofac_name_dob_smt_siblings;

    disclose_circuit.ofac_name_yob_smt_leaf_key <== ofac_name_yob_smt_leaf_key;
    disclose_circuit.ofac_name_yob_smt_root <== ofac_name_yob_smt_root;
    disclose_circuit.ofac_name_yob_smt_siblings <== ofac_name_yob_smt_siblings;

    disclose_circuit.selector_ofac <== selector_ofac;

    var revealed_data_packed_chunk_length = computeIntChunkLength(selfrica_length + 2);
    signal output revealedData_packed[revealed_data_packed_chunk_length] <== disclose_circuit.revealedData_packed;

    var forbidden_countries_list_packed_chunk_length = computeIntChunkLength(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH * country_length);
    signal output forbidden_countries_list_packed[forbidden_countries_list_packed_chunk_length] <== disclose_circuit.forbidden_countries_list_packed;
}


component main {
    public [ 
        pubKeyX, 
        pubKeyY,
        scope, 
        ofac_name_dob_smt_root, 
        ofac_name_yob_smt_root,
        attestation_id
    ]
} = VC_AND_DISCLOSE(3, 64, 64);