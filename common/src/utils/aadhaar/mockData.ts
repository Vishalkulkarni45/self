import { generateTestData, testCustomData } from "./utils.js";
import {
  convertBigIntToByteArray,
  decompressByteArray,
  splitToWords,
  extractPhoto,
} from '@anon-aadhaar/core';
import { bufferToHex, Uint8ArrayToCharArray } from "@zk-email/helpers/dist/binary-format.js";
import { sha256Pad } from '@zk-email/helpers/dist/sha-utils.js';
import { testQRData } from "./assets/dataInput.js";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { stringToAsciiArray } from "./utils.js";
import { packBytesAndPoseidon } from "../hash.js";
import { poseidon5 } from "poseidon-lite";
let QRData: string = testQRData.testQRData;

export function prepareAadhaarTestData(privateKeyPath: string, publicKeyPath: string, name?: string, dateOfBirth?: string, gender?: string, pincode?: string, state?: string) {
  // Set default values for any parameters that weren't provided
  const finalName = name ?? 'SUMIT KUMAR';
  const finalDateOfBirth = dateOfBirth ?? '01-01-1984';
  const finalGender = gender ?? 'M';
  const finalPincode = pincode ?? '110051';
  const finalState = state ?? 'Delhi';

  let qrDataBytes: any;
  if(name || dateOfBirth || gender || pincode || state) {
    const newTestData = generateTestData({ privateKeyPath, data: testCustomData, name: finalName, dob: finalDateOfBirth, gender: finalGender, pincode: finalPincode, state: finalState});
    qrDataBytes = convertBigIntToByteArray(BigInt(newTestData.testQRData));
  }else{
    name = 'SUMIT KUMAR';
    dateOfBirth = '01-01-1984';
    gender = 'M';
    pincode = '110051';
    state = 'Delhi';
    qrDataBytes = convertBigIntToByteArray(BigInt(QRData));
  }

  const decodedData = decompressByteArray(qrDataBytes);
  const signatureBytes = decodedData.slice(decodedData.length - 256, decodedData.length);
  const signedData = decodedData.slice(0, decodedData.length - 256);

  const [qrDataPadded, qrDataPaddedLen] = sha256Pad(signedData, 512 * 3);

  const delimiterIndices: number[] = [];
  for (let i = 0; i < qrDataPadded.length; i++) {
    if (qrDataPadded[i] === 255) {
      delimiterIndices.push(i);
    }
    if (delimiterIndices.length === 18) {
      break;
    }
  }

  const signature = BigInt('0x' + bufferToHex(Buffer.from(signatureBytes)).toString());

  const pkPem = fs.readFileSync(path.join(publicKeyPath));
  const pk = crypto.createPublicKey(pkPem);

  const pubKey = BigInt(
    '0x' + bufferToHex(Buffer.from(pk.export({ format: 'jwk' }).n as string, 'base64url'))
  );

  const paddedName = finalName
    .padEnd(62, '\0')
    .split('')
    .map((char) => char.charCodeAt(0));

  const [dob, mob, yob] = finalDateOfBirth.split('-');

  const nullifierArgs = [stringToAsciiArray(finalGender)[0], ...stringToAsciiArray(yob), ...stringToAsciiArray(mob), ...stringToAsciiArray(dob), ...paddedName, ...stringToAsciiArray('2697')];
  const nullifier = packBytesAndPoseidon(nullifierArgs);

  const qrHash = packBytesAndPoseidon(Array.from(qrDataPadded));
  const photo = extractPhoto(Array.from(qrDataPadded), qrDataPaddedLen);
  const photoHash = packBytesAndPoseidon(photo.bytes.map(Number));

  const packedCommitmentArgs = [3, ...stringToAsciiArray(finalPincode), ...stringToAsciiArray(finalState.padEnd(31, '\0')), ...stringToAsciiArray('1234')];
  const packedCommitment = packBytesAndPoseidon(packedCommitmentArgs);

  // Final commitment hash using Poseidon(5) - matches circuit structure
  const commitment = poseidon5([BigInt(1234), BigInt(qrHash), BigInt(nullifier), BigInt(packedCommitment), BigInt(photoHash)]);

  const inputs = {
    qrDataPadded: Uint8ArrayToCharArray(qrDataPadded),
    qrDataPaddedLength: qrDataPaddedLen,
    delimiterIndices: delimiterIndices,
    signature: splitToWords(signature, BigInt(121), BigInt(17)),
    pubKey: splitToWords(pubKey, BigInt(121), BigInt(17)),
    secret: '1234',
    attestation_id: '3',
  };

  return {
    inputs,
    nullifier,
    commitment,
  };
}
