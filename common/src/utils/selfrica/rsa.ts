
import crypto from "crypto";

// Generate a new RSA key pair (rsa_sha256_65537_2048)
function generateRSAKeyPair() {
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048, // 2048-bit key
    publicExponent: 65537, // Standard exponent for RSA-65537
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
    },
  });

}


function signRSA(message: Buffer, privateKey: string) {

  // Sign the message using RSA-SHA256 with PKCS#1 v1.5 padding (rsa_sha256_65537_2048 - algorithm 1)
  const signature = crypto.sign("RSA-SHA256", message, {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PADDING, // PKCS#1 v1.5 padding, not PSS
  });

  return signature;
}

function verifyRSA(message: Buffer, signatureBuffer: Buffer, publicKey: string) {
  // Create the verifier. The algorithm must match the algorithm of the key.
  const verify = crypto.createVerify("sha256");
  verify.update(message);
  verify.end();

  // Build the key object with PKCS#1 v1.5 padding
  const key = {
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PADDING, // PKCS#1 v1.5 padding to match signing
  };

  // Verify the signature using the public key
  const verified = verify.verify(key, signatureBuffer);
  return verified;
}

export { generateRSAKeyPair, signRSA, verifyRSA};
