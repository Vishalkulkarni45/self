pragma circom 2.1.9;

include "circomlib/circuits/poseidon.circom";
include "@openpassport/zk-email-circuits/lib/sha.circom";
include "@openpassport/zk-email-circuits/lib/rsa.circom";


/// @title SignatureVerifier
/// @notice Verifies Aadhaar signature
/// @param n - RSA pubic key size per chunk
/// @param k - Number of chunks the RSA public key is split into
/// @param maxDataLength - Maximum length of the data
/// @input qrDataPadded - QR data without the signature; each number represent ascii byte; remaining space is padded with 0
/// @input qrDataPaddedLength - Length of padded QR data
/// @input signature - RSA signature
/// @input pubKey - RSA public key
template SignatureVerifier(n, k, maxDataLength) {
    signal input qrDataPadded[maxDataLength];
    signal input qrDataPaddedLength;
    signal input signature[k];
    signal input pubKey[k];


    // Hash the data and verify RSA signature - 917344 constraints
    component shaHasher = Sha256Bytes(maxDataLength);
    shaHasher.paddedIn <== qrDataPadded;
    shaHasher.paddedInLength <== qrDataPaddedLength;
    signal sha[256];
    sha <== shaHasher.out;

    component rsa = RSAVerifier65537(n, k);
    var rsaMsgLength = (256 + n) \ n;
    component rsaBaseMsg[rsaMsgLength];
    for (var i = 0; i < rsaMsgLength; i++) {
        rsaBaseMsg[i] = Bits2Num(n);
    }
    for (var i = 0; i < 256; i++) {
        rsaBaseMsg[i \ n].in[i % n] <== sha[255 - i];
    }
    for (var i = 256; i < n * rsaMsgLength; i++) {
        rsaBaseMsg[i \ n].in[i % n] <== 0;
    }

    for (var i = 0; i < rsaMsgLength; i++) {
        rsa.message[i] <== rsaBaseMsg[i].out;
    }
    for (var i = rsaMsgLength; i < k; i++) {
        rsa.message[i] <== 0;
    }

	rsa.modulus <== pubKey;
	rsa.signature <== signature;

}
