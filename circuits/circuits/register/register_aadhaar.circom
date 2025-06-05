pragma circom 2.1.9;

include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "../utils/aadhaar/extractQrData.circom";
include "../utils/aadhaar/signature.circom";
include "../utils/passport/customHashers.circom";

/// @title: AadhaarRegister
/// @notice Main circuit — verifies the integrity of the aadhaar data, the signature, and generates commitment and nullifier
/// @param n RSA pubic key size per chunk
/// @param k Number of chunks the RSA public key is split into
/// @param maxDataLength Maximum length of the data
/// @input qrDataPadded QR data without the signature; assumes elements to be bytes; remaining space is padded with 0
/// @input qrDataPaddedLength Length of padded QR data
/// @input delimiterIndices Indices of delimiters (255) in the QR text data. 18 delimiters including photo
/// @input signature RSA signature
/// @input pubKey RSA public key (of the government)
/// @output nullifier Generated nullifier - deterministic on the Aadhaar data
/// @output commitment Commitment that will be added to the onchain registration tree

template REGISTER_AADHAAR(n, k, maxDataLength){

    signal input qrDataPadded[maxDataLength];
    signal input qrDataPaddedLength;
    signal input delimiterIndices[18];
    signal input pubKey[k];
    signal input signature[k];

    signal input secret;
    // Aadhaar = 6
    signal input attestation_id;


  // Assert `qrDataPaddedLength` fits in `ceil(log2(maxDataLength))`
  //TODO: how to use log2Ceil?
  //  component n2bHeaderLength = Num2Bits(log2Ceil(maxDataLength));
    component n2bHeaderLength = Num2Bits(11);
    n2bHeaderLength.in <== qrDataPaddedLength;

    // Verify the RSA signature
    component signatureVerifier = SignatureVerifier(n, k, maxDataLength);
    signatureVerifier.qrDataPadded <== qrDataPadded;
    signatureVerifier.qrDataPaddedLength <== qrDataPaddedLength;
    signatureVerifier.pubKey <== pubKey;
    signatureVerifier.signature <== signature;



    // Assert data between qrDataPaddedLength and maxDataLength is zero
    AssertZeroPadding(maxDataLength)(qrDataPadded, qrDataPaddedLength);

    component qrDataExtractor = EXTRACT_QR_DATA(maxDataLength);
    qrDataExtractor.data <== qrDataPadded;
    qrDataExtractor.qrDataPaddedLength <== qrDataPaddedLength;
    qrDataExtractor.delimiterIndices <== delimiterIndices;

    signal output nullifier <== Poseidon(7)([
        qrDataExtractor.gender,
        qrDataExtractor.yob,
        qrDataExtractor.mob,
        qrDataExtractor.dob,
        qrDataExtractor.name[0],
        qrDataExtractor.name[1],
        qrDataExtractor.aadhaar_last_4digits
    ]);


    signal qrDataHash <== PackBytesAndPoseidon(maxDataLength)(qrDataPadded);


    //TODO: should i replace gender,yob,name with nullifier ?
    signal output commitment <== Poseidon(13)([
        attestation_id,
        secret,
        qrDataHash,
        qrDataExtractor.gender,
        qrDataExtractor.yob,
        qrDataExtractor.mob,
        qrDataExtractor.dob,
        qrDataExtractor.name[0],
        qrDataExtractor.name[1],
        qrDataExtractor.aadhaar_last_4digits,
        qrDataExtractor.pincode,
        qrDataExtractor.ph_no_last_4digits,
        qrDataExtractor.photoHash
    ]);

}


component main = REGISTER_AADHAAR(121, 17, 512 * 3);
