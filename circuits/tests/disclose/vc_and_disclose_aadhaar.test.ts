import { expect } from 'chai';
import { wasm as wasmTester } from 'circom_tester';
import path from 'path';

import { sha256Pad } from '@zk-email/helpers/dist/sha-utils';
import {
  bigIntToChunkedBytes,
  bufferToHex,
  Uint8ArrayToCharArray,
} from '@zk-email/helpers/dist/binary-format';
import {
  convertBigIntToByteArray,
  decompressByteArray,
  splitToWords,
  extractPhoto,
  timestampToUTCUnix,
} from '@anon-aadhaar/core';

import fs from 'fs';
import crypto from 'crypto';
import assert from 'assert';
import { testQRData } from '../assets/dataInput.json';
import { packBytesAndPoseidon } from '../../../common/src/utils/hash';
import { poseidon12, poseidon2, poseidon3, poseidon7 } from 'poseidon-lite';
import { packBytes } from '../../../common/src/utils/bytes';
import { LeanIMT } from '@openpassport/zk-kit-lean-imt';
import { findIndexInTree, formatInput } from '../../../common/src/utils/circuits/generateInputs';
import { generateMerkleProof } from '../../../common/src/utils/trees';
import { COMMITMENT_TREE_DEPTH } from '../../../common/src/constants/constants';

let QRData: string = testQRData;

function prepareTestData() {
  const qrDataBytes = convertBigIntToByteArray(BigInt(QRData));
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

  const pkPem = fs.readFileSync(path.join(__dirname, '../assets/testPublicKey.pem'));
  const pk = crypto.createPublicKey(pkPem);

  const pubKey = BigInt(
    '0x' + bufferToHex(Buffer.from(pk.export({ format: 'jwk' }).n as string, 'base64url'))
  );

  const paddedName = 'Sumit Kumar'
    .padEnd(62, '\0')
    .split('')
    .map((char) => char.charCodeAt(0));
  const name = packBytes(paddedName);
  const dobHash = poseidon3(['1984', '1', '1']);

  const nullifier = poseidon7([
    BigInt(77),
    BigInt(1984),
    BigInt(1),
    BigInt(1),
    name[0],
    name[1],
    BigInt(2697),
  ]);
  const qrHash = packBytesAndPoseidon(Array.from(qrDataPadded));
  const commitment = poseidon12([
    BigInt(6),
    BigInt(1234),
    qrHash,
    BigInt(77),
    BigInt(1984),
    BigInt(1),
    BigInt(1),
    name[0],
    name[1],
    BigInt(2697),
    BigInt(110051),
    BigInt(1234),
  ]);
  const tree: any = new LeanIMT((a, b) => poseidon2([a, b]), []);
  tree.insert(BigInt(commitment));

  const index = findIndexInTree(tree, commitment);
  const {
    siblings,
    path: merkle_path,
    leaf_depth,
  } = generateMerkleProof(tree, index, COMMITMENT_TREE_DEPTH);

  const inputs = {
    attestation_id: '6',
    secret: '1234',
    qrDataHash: qrHash,
    gender: '77',
    yob: '1984',
    mob: '1',
    dob: '1',
    name: formatInput(name.slice(0, 2)),
    aadhaar_last_4digits: '2697',
    pincode: '110051',
    ph_no_last_4digits: '1234',
    merkle_root: formatInput(tree.root),
    leaf_depth: formatInput(leaf_depth),
    path: formatInput(merkle_path),
    siblings: formatInput(siblings),
  };

  return {
    inputs,
    nullifier,
    commitment,
  };
}

describe(' VC and Disclose Aadhaar Circuit Tests', function () {
  let circuit: any;
  this.beforeAll(async function () {
    this.timeout(0);
    circuit = await wasmTester(
      path.join(__dirname, '../../circuits/disclose/vc_and_disclose_aadhaar.circom'),
      {
        verbose: true,
        logOutput: true,
        include: ['node_modules', './node_modules/circomlib/circuits'],
      }
    );
  });

  it('should compile and load the circuit', async function () {
    this.timeout(0);
    expect(circuit).to.not.be.undefined;
  });
  it.only('should calculate witness and pass constrain check', async function () {
    this.timeout(0);
    const { inputs } = prepareTestData();
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);
  });
});
