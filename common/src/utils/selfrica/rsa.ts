
import crypto from "crypto";

// Generate a new RSA key pair
function generateRSAKeyPair() {
  return crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048,
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
  // Sign the message directly with the private key
  const signature = crypto.sign("RSA-SHA256", message, {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  });

  // Example of how to display signature. Because the signature is in a binary
  // format, you need to encode the output before printing it to a console or
  // displaying it on a screen.
  const encoded = signature.toString("base64");
  console.log(`Signature: ${encoded}`);

  return signature;
}

function verifyRSA(message: Buffer, signatureBuffer: Buffer, publicKey: string) {
  // Create the verifier. The algorithm must match the algorithm of the key.
  const verify = crypto.createVerify("sha256");
  verify.update(message);
  verify.end();

  // Build the key object
  const key = {
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
  };

  // Verify the signature using the public key
  const verified = verify.verify(key, signatureBuffer);
  return verified;
}

export { generateRSAKeyPair, signRSA, verifyRSA};
