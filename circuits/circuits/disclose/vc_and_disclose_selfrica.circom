pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "circomlib/circuits/bitify.circom";
include "../utils/selfrica/verifySignature.circom";
include "../utils/passport/signatureVerifier.circom";
include "../utils/passport/customHashers.circom";
include "@openpassport/zk-email-circuits/lib/sha.circom";
include "@openpassport/zk-email-circuits/lib/bigint.circom";
include "../utils/selfrica/constants.circom";
include "../utils/selfrica/disclose/disclose.circom";

template VC_AND_DISCLOSE(
    MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH,
    namedobTreeLevels,
    nameyobTreeLevels,
    n,
    k
) {
    var selfrica_length = SELFRICA_MAX_LENGTH();
    var country_length = COUNTRY_LENGTH();

    signal input SmileID_data_padded[SMILE_DATA_PADDED()];
    signal input disclose_sel[selfrica_length];

    signal input pubKey[k];
    signal input msg_sig[k];
    signal input id_num_sig[k];

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
    signal input user_identifier;
    signal input current_date[8];
    signal input majority_age_ASCII[3];
    signal input selector_older_than;



    //range check not needed for SmileID_data_padded to be ascii
    for(var i = 0; i < selfrica_length; i++){
        //Check is selctor binary
        disclose_sel[i] * (disclose_sel[i] - 1) === 0;
    }


    //skiped  paddedInLength to be within `ceil(log2(8 * maxByteLength))` bits bez we are using hardcoded values
    component msg_hasher = Sha256Bytes(SMILE_DATA_PADDED());
    msg_hasher.paddedIn <== SmileID_data_padded;
    msg_hasher.paddedInLength <== SMILE_DATA_PADDED();

    //verify Hash(smiledata) signatur
    component msg_sig_verify = SignatureVerifier(1, n, k);
    msg_sig_verify.hash <== msg_hasher.out;
    msg_sig_verify.pubKey <== pubKey;
    msg_sig_verify.signature <== msg_sig;


    //Calculate IDNUMBER hash
    signal id_num[SMILE_ID_PADDED()];
    var idNumberIdx = ID_NUMBER_INDEX();

    // Fill the first 20 bytes with actual ID number data
    for (var i = 0; i < ID_NUMBER_LENGTH(); i++) {
        id_num[i] <== SmileID_data_padded[idNumberIdx + i];
    }

    // Add SHA-256 padding for 20-byte message
    // Add padding bit '1' (0x80)
    id_num[ID_NUMBER_LENGTH()] <== 128; // 0x80 in decimal

    // Fill with zeros up to position 56 (64 - 8 for length field)
    for (var i = ID_NUMBER_LENGTH() + 1; i < SMILE_ID_PADDED() - 8; i++) {
        id_num[i] <== 0;
    }

    // Add 64-bit length field (20 bytes * 8 = 160 bits)
    // Length in bits as 64-bit big-endian integer
    for (var i = SMILE_ID_PADDED() - 8; i < SMILE_ID_PADDED() - 1; i++) {
        id_num[i] <== 0; // High bytes are 0 for small lengths
    }
    id_num[SMILE_ID_PADDED() - 1] <== 160; // 20 * 8 = 160 bits

    component id_num_hasher = Sha256Bytes(SMILE_ID_PADDED());
    id_num_hasher.paddedIn <== id_num;
    id_num_hasher.paddedInLength <== SMILE_ID_PADDED();

    //verify Hash(IdNumber) signature
    component id_num_sig_verify = SignatureVerifier(1, n, k);
    id_num_sig_verify.hash <== id_num_hasher.out;
    id_num_sig_verify.pubKey <== pubKey;
    id_num_sig_verify.signature <== id_num_sig;


    // Identity Commitment = Hash( IdNumCommit sig )
    component idCommCal = CustomHasher(k);
    idCommCal.in <== msg_sig;

    //Nullifier = HASH( nullifier sig , scope )
    component nullifierCal = CustomHasher(k + 1);
    for (var i = 0; i < k; i++) {
        nullifierCal.in[i] <== id_num_sig[i];
    }
    nullifierCal.in[k] <== scope;

    component disclose_circuit = DISCLOSE_SELFRICA(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH, namedobTreeLevels, nameyobTreeLevels);

    for (var i = 0; i < selfrica_length; i++) {
        disclose_circuit.smile_data[i] <== SmileID_data_padded[i];
    }
    disclose_circuit.selector_smile_data <== disclose_sel;
    disclose_circuit.forbidden_countries_list <== forbidden_countries_list;

    disclose_circuit.ofac_name_dob_smt_leaf_key <== ofac_name_dob_smt_leaf_key;
    disclose_circuit.ofac_name_dob_smt_root <== ofac_name_dob_smt_root;
    disclose_circuit.ofac_name_dob_smt_siblings <== ofac_name_dob_smt_siblings;

    disclose_circuit.ofac_name_yob_smt_leaf_key <== ofac_name_yob_smt_leaf_key;
    disclose_circuit.ofac_name_yob_smt_root <== ofac_name_yob_smt_root;
    disclose_circuit.ofac_name_yob_smt_siblings <== ofac_name_yob_smt_siblings;

    disclose_circuit.selector_ofac <== selector_ofac;
    disclose_circuit.current_date <== current_date;
    disclose_circuit.majority_age_ASCII <== majority_age_ASCII;
    disclose_circuit.selector_older_than <== selector_older_than;

    var revealed_data_packed_chunk_length = computeIntChunkLength(selfrica_length + 2 + 3);
    signal output revealedData_packed[revealed_data_packed_chunk_length] <== disclose_circuit.revealedData_packed;

    var forbidden_countries_list_packed_chunk_length = computeIntChunkLength(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH * country_length);
    signal output forbidden_countries_list_packed[forbidden_countries_list_packed_chunk_length] <== disclose_circuit.forbidden_countries_list_packed;

    signal output identity_commitment <== idCommCal.out;
    signal output nullifier <== nullifierCal.out;

    //dummy constrain
    signal dummy <== user_identifier * attestation_id;
}

component main {
    public [
        scope,
        user_identifier,
        current_date,
        ofac_name_dob_smt_root,
        ofac_name_yob_smt_root,
        attestation_id
    ]
} = VC_AND_DISCLOSE(40, 64, 64, 121, 17);
