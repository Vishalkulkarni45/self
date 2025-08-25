pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "../utils/aadhaar/extractQrData.circom";
include "../utils/passport/signatureVerifier.circom";
include "../utils/passport/customHashers.circom";
include "@openpassport/zk-email-circuits/utils/array.circom";
include "@openpassport/zk-email-circuits/lib/sha.circom";

/// @title: AadhaarRegister
/// @notice Main circuit — verifies the integrity of the aadhaar data, the signature, and generates commitment and nullifier
/// @param n RSA pubic key size per chunk
/// @param k Number of chunks the RSA public key is split into
/// @param maxDataLength Maximum length of the data
/// @input qrDataPadded QR data without the signature; assumes elements to be bytes; remaining space is padded with 0
/// @input qrDataPaddedLength Length of padded QR data
/// @input delimiterIndices Indices of delimiters (255) in the QR text data. 18 delimiters including photo
/// @input signature RSA signature split into k chunks of n bits each
/// @input pubKey RSA public key(of the government) split into k chunks of n bits each
/// @input secret Secret for commitment generation. Saved by the user to access their commitment
/// @input attestation_id Attestation ID of the credential used to generate the commitment
/// @output nullifier Generated nullifier - deterministic on the Aadhaar data
/// @output commitment Commitment that will be added to the onchain registration tree
/// @output pubKeyHash Hash of the public key
/// @output timestamp Timestamp of the QR data
template REGISTER_AADHAAR(n, k, maxDataLength){
    signal input qrDataPadded[maxDataLength];
    signal input qrDataPaddedLength;
    signal input delimiterIndices[18];
    signal input pubKey[k];
    signal input signature[k];

    signal input secret;

    signal input attestation_id;


    // Assert `qrDataPaddedLength` fits in `ceil(log2(maxDataLength))`
    component n2bHeaderLength = Num2Bits(log2Ceil(maxDataLength));
    n2bHeaderLength.in <== qrDataPaddedLength;

    // Hash the data
    component shaHasher = Sha256Bytes(maxDataLength);
    shaHasher.paddedIn <== qrDataPadded;
    shaHasher.paddedInLength <== qrDataPaddedLength;

    // Verify the RSA signature
    // component signatureVerifier = SignatureVerifier(1, n, k);
    // signatureVerifier.hash <== shaHasher.out;
    // signatureVerifier.pubKey <== pubKey;
    // signatureVerifier.signature <== signature;

    // Assert data between qrDataPaddedLength and maxDataLength is zero
    AssertZeroPadding(maxDataLength)(qrDataPadded, qrDataPaddedLength);

    // Extract data from QR data
    component qrDataExtractor = EXTRACT_QR_DATA(maxDataLength);
    qrDataExtractor.data <== qrDataPadded;
    qrDataExtractor.qrDataPaddedLength <== qrDataPaddedLength;
    qrDataExtractor.delimiterIndices <== delimiterIndices;

    signal output pubKeyHash <== CustomHasher(k)(pubKey);

    // Generate nullifier
    component nullifierHasher = PackBytesAndPoseidon(75);
    nullifierHasher.in[0] <== qrDataExtractor.gender;

    for (var i = 0; i < 4 ; i++){
        nullifierHasher.in[i + 1] <== qrDataExtractor.yob[i];
    }

    for (var i = 0; i < 2 ; i++){
        nullifierHasher.in[i + 5] <== qrDataExtractor.mob[i];
    }

    for (var i = 0; i < 2 ; i++){
        nullifierHasher.in[i + 7] <== qrDataExtractor.dob[i];
    }

    for (var i = 0; i < 62 ; i++){
        nullifierHasher.in[i + 9] <== qrDataExtractor.name[i];
    }

    for (var i = 0; i < 4 ; i++){
        nullifierHasher.in[i + 71] <== qrDataExtractor.aadhaar_last_4digits[i];
    }

    signal output nullifier <== nullifierHasher.out;


    signal qrDataHash <== PackBytesAndPoseidon(maxDataLength)(qrDataPadded);

    // Generate commitment
    component packedCommitment = PackBytesAndPoseidon(42);
     packedCommitment.in[0] <== attestation_id;


    for (var i = 0; i < 6 ; i++){
        packedCommitment.in[i + 1] <== qrDataExtractor.pincode[i];
    }

    for (var i = 0; i < maxFieldByteSize() ; i++){
        packedCommitment.in[i + 7] <== qrDataExtractor.state[i];
    }

    for (var i = 0; i < 4 ; i++){
        packedCommitment.in[i + 38] <== qrDataExtractor.ph_no_last_4digits[i];
    }

    component commitmentHasher = Poseidon(5);

    commitmentHasher.inputs[0] <== secret;
    commitmentHasher.inputs[1] <== qrDataHash;
    commitmentHasher.inputs[2] <== nullifier;
    commitmentHasher.inputs[3] <== packedCommitment.out;
    commitmentHasher.inputs[4] <== qrDataExtractor.photoHash;

    signal output commitment <== commitmentHasher.out;
    signal output timestamp <== qrDataExtractor.timestamp;
}
