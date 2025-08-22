import { calculateAge, generateTestData, testCustomData } from "./utils.js";
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
import { poseidon2, poseidon5 } from "poseidon-lite";
import { LeanIMT } from "@openpassport/zk-kit-lean-imt";
import { SMT } from "@openpassport/zk-kit-smt";
import { findIndexInTree, formatInput } from "../circuits/generateInputs.js";
import { generateMerkleProof, generateSMTProof, getNameDobLeafAadhaar, getNameYobLeafAahaar } from "../trees.js";

import { COMMITMENT_TREE_DEPTH } from "../../constants/constants.js";
import { extractQRDataFields } from './utils.js';


let QRData: string = testQRData.testQRData;

// Helper function to compute padded name
function computePaddedName(name: string): number[] {
  return name
    .padEnd(62, '\0')
    .split('')
    .map((char) => char.charCodeAt(0));
}

// Helper function to compute nullifier
function computeNullifier(extractedFields: ReturnType<typeof extractQRDataFields>, paddedName: number[]): bigint {
  const genderAscii = stringToAsciiArray(extractedFields.gender)[0];
  const nullifierArgs = [
    genderAscii,
    ...stringToAsciiArray(extractedFields.yob),
    ...stringToAsciiArray(extractedFields.mob),
    ...stringToAsciiArray(extractedFields.dob),
    ...paddedName,
    ...stringToAsciiArray(extractedFields.aadhaarLast4Digits)
  ];
  return BigInt(packBytesAndPoseidon(nullifierArgs));
}

// Helper function to compute packed commitment
function computePackedCommitment(extractedFields: ReturnType<typeof extractQRDataFields>): bigint {
  const packedCommitmentArgs = [
    3,
    ...stringToAsciiArray(extractedFields.pincode),
    ...stringToAsciiArray(extractedFields.state.padEnd(31, '\0')),
    ...stringToAsciiArray(extractedFields.phoneNoLast4Digits)
  ];
  return BigInt(packBytesAndPoseidon(packedCommitmentArgs));
}

// Helper function to compute final commitment
function computeCommitment(
  qrHash: bigint,
  nullifier: bigint,
  packedCommitment: bigint,
  photoHash: bigint,
  secret: bigint
): bigint {
  return poseidon5([
    secret,
    qrHash,
    nullifier,
    packedCommitment,
    photoHash
  ]);
}

interface SharedQRData {
  qrDataBytes: any;
  decodedData: Uint8Array;
  signedData: Uint8Array;
  qrDataPadded: Uint8Array;
  qrDataPaddedLen: number;
  extractedFields: ReturnType<typeof extractQRDataFields>;
  qrHash: bigint;
  photo: { bytes: number[]; };
  photoHash: bigint;
}

function processQRData(privateKeyPath: string, name?: string, dateOfBirth?: string, gender?: string, pincode?: string, state?: string, timestamp?: string): SharedQRData {
  const finalName = name ?? 'Sumit Kumar';
  const finalDateOfBirth = dateOfBirth ?? '01-01-1984';
  const finalGender = gender ?? 'M';
  const finalPincode = pincode ?? '110051';
  const finalState = state ?? 'Delhi';

  let qrDataBytes: any;
  if(name || dateOfBirth || gender || pincode || state) {
    const newTestData = generateTestData({ privateKeyPath, data: testCustomData, name: finalName, dob: finalDateOfBirth, gender: finalGender, pincode: finalPincode, state: finalState, timestamp: timestamp});
    qrDataBytes = convertBigIntToByteArray(BigInt(newTestData.testQRData));
  } else {
    qrDataBytes = convertBigIntToByteArray(BigInt(QRData));
  }

  const decodedData = decompressByteArray(qrDataBytes);
  const signedData = decodedData.slice(0, decodedData.length - 256);

  const [qrDataPadded, qrDataPaddedLen] = sha256Pad(signedData, 512 * 3);

  // Extract actual fields from QR data instead of using hardcoded values
  const extractedFields = extractQRDataFields(qrDataBytes);

  const qrHash = packBytesAndPoseidon(Array.from(qrDataPadded));
  const photo = extractPhoto(Array.from(qrDataPadded), qrDataPaddedLen);
  const photoHash = packBytesAndPoseidon(photo.bytes.map(Number));

  return {
    qrDataBytes,
    decodedData,
    signedData,
    qrDataPadded,
    qrDataPaddedLen,
    extractedFields,
    qrHash: BigInt(qrHash),
    photo,
    photoHash: BigInt(photoHash)
  };
}

export function prepareAadhaarRegisterTestData(privateKeyPath: string, publicKeyPath: string,secret: string, name?: string, dateOfBirth?: string, gender?: string, pincode?: string, state?: string, timestamp?: string) {

  const sharedData = processQRData(privateKeyPath, name, dateOfBirth, gender, pincode, state, timestamp);
  const delimiterIndices: number[] = [];
  for (let i = 0; i < sharedData.qrDataPadded.length; i++) {
    if (sharedData.qrDataPadded[i] === 255) {
      delimiterIndices.push(i);
    }
    if (delimiterIndices.length === 18) {
      break;
    }
  }

  const signatureBytes = sharedData.decodedData.slice(sharedData.decodedData.length - 256, sharedData.decodedData.length);
  const signature = BigInt('0x' + bufferToHex(Buffer.from(signatureBytes)).toString());

  const pkPem = fs.readFileSync(path.join(publicKeyPath));
  const pk = crypto.createPublicKey(pkPem);
  const pubKey = BigInt(
    '0x' + bufferToHex(Buffer.from(pk.export({ format: 'jwk' }).n as string, 'base64url'))
  );

  const paddedName = computePaddedName(sharedData.extractedFields.name);
  const nullifier = computeNullifier(sharedData.extractedFields, paddedName);
  const packedCommitment = computePackedCommitment(sharedData.extractedFields);
  const commitment = computeCommitment(
    BigInt(secret),
    BigInt(sharedData.qrHash),
    nullifier,
    packedCommitment,
    BigInt(sharedData.photoHash)
  );

  const inputs = {
    qrDataPadded: Uint8ArrayToCharArray(sharedData.qrDataPadded),
    qrDataPaddedLength: sharedData.qrDataPaddedLen,
    delimiterIndices: delimiterIndices,
    signature: splitToWords(signature, BigInt(121), BigInt(17)),
    pubKey: splitToWords(pubKey, BigInt(121), BigInt(17)),
    secret: secret,
    attestation_id: '3',
  };

  return {
    inputs,
    nullifier,
    commitment,
  };
}

export function prepareAadhaarDiscloseTestData(
  privateKeyPath: string,
  merkletree: LeanIMT,
  nameAndDob_smt: SMT,
  nameAndYob_smt: SMT,
  scope: string,
  secret: string,
  user_identifier: string,
  name?: string,
  dateOfBirth?: string,
  gender?: string,
  pincode?: string,
  state?: string,
  timestamp?: string,
) {
  const sharedData = processQRData(privateKeyPath, name, dateOfBirth, gender, pincode, state, timestamp);

  const {age, currentYear, currentMonth, currentDay } = calculateAge(sharedData.extractedFields.dob, sharedData.extractedFields.mob, sharedData.extractedFields.yob);

  const paddedName = computePaddedName(sharedData.extractedFields.name);
  const genderAscii = stringToAsciiArray(sharedData.extractedFields.gender)[0];
  const nullifier = computeNullifier(sharedData.extractedFields, paddedName);
  const packedCommitment = computePackedCommitment(sharedData.extractedFields);
  const commitment = computeCommitment(
    BigInt(secret),
    BigInt(sharedData.qrHash),
    nullifier,
    packedCommitment,
    BigInt(sharedData.photoHash)
  );

  merkletree.insert(BigInt(commitment));

  const index = findIndexInTree(merkletree, BigInt(commitment));
  const {
    siblings,
    path: merkle_path,
    leaf_depth,
  } = generateMerkleProof(merkletree, index, COMMITMENT_TREE_DEPTH);

  const namedob_leaf = getNameDobLeafAadhaar(sharedData.extractedFields.name, sharedData.extractedFields.yob, sharedData.extractedFields.mob, sharedData.extractedFields.dob);
  const nameyob_leaf = getNameYobLeafAahaar(sharedData.extractedFields.name, sharedData.extractedFields.yob);

  const {
    root: ofac_name_dob_smt_root,
    closestleaf: ofac_name_dob_smt_leaf_key,
    siblings: ofac_name_dob_smt_siblings,
  } = generateSMTProof(nameAndDob_smt, namedob_leaf);

  const {
    root: ofac_name_yob_smt_root,
    closestleaf: ofac_name_yob_smt_leaf_key,
    siblings: ofac_name_yob_smt_siblings,
  } = generateSMTProof(nameAndYob_smt, nameyob_leaf);

  const inputs = {
    attestation_id: '3',
    secret: secret,
    qrDataHash: sharedData.qrHash,
    gender: genderAscii.toString(),
    yob: stringToAsciiArray(sharedData.extractedFields.yob),
    mob: stringToAsciiArray(sharedData.extractedFields.mob),
    dob: stringToAsciiArray(sharedData.extractedFields.dob),
    name: formatInput(paddedName),
    aadhaar_last_4digits: stringToAsciiArray(sharedData.extractedFields.aadhaarLast4Digits),
    pincode: stringToAsciiArray(sharedData.extractedFields.pincode),
    state: stringToAsciiArray(sharedData.extractedFields.state.padEnd(31, '\0')),
    ph_no_last_4digits: stringToAsciiArray(sharedData.extractedFields.phoneNoLast4Digits),
    photoHash: formatInput(BigInt(sharedData.photoHash)),
    merkle_root: formatInput(merkletree.root),
    leaf_depth: formatInput(leaf_depth),
    path: formatInput(merkle_path),
    siblings: formatInput(siblings),
    ofac_name_dob_smt_leaf_key: formatInput(ofac_name_dob_smt_leaf_key),
    ofac_name_dob_smt_root: formatInput(ofac_name_dob_smt_root),
    ofac_name_dob_smt_siblings: formatInput(ofac_name_dob_smt_siblings),
    ofac_name_yob_smt_leaf_key: formatInput(ofac_name_yob_smt_leaf_key),
    ofac_name_yob_smt_root: formatInput(ofac_name_yob_smt_root),
    ofac_name_yob_smt_siblings: formatInput(ofac_name_yob_smt_siblings),
    selector: '0',
    minimumAge: formatInput(age - 2),
    currentYear: formatInput(currentYear),
    currentMonth: formatInput(currentMonth),
    currentDay: formatInput(currentDay),
    scope: formatInput(scope),
    user_identifier: formatInput(user_identifier),
  };

  return {
    inputs,
  };
}
