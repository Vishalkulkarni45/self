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
import { poseidon12, poseidon13, poseidon14, poseidon3, poseidon7 } from 'poseidon-lite';
import { packBytes } from '../../../common/src/utils/bytes';

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
  const photo = extractPhoto(Array.from(qrDataPadded), qrDataPaddedLen);
  const photoHash = packBytesAndPoseidon(photo.bytes.map(Number));
  const commitment = poseidon14([
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
    BigInt(452723500356),
    BigInt(1234),
    BigInt(photoHash)
  ]);

  const inputs = {
    qrDataPadded: Uint8ArrayToCharArray(qrDataPadded),
    qrDataPaddedLength: qrDataPaddedLen,
    delimiterIndices: delimiterIndices,
    signature: splitToWords(signature, BigInt(121), BigInt(17)),
    pubKey: splitToWords(pubKey, BigInt(121), BigInt(17)),
    secret: '1234',
    attestation_id: '6',
  };

  return {
    inputs,
    nullifier,
    commitment,
  };
}

describe(' REGISTER AADHAAR Circuit Tests', function () {
  let circuit: any;
  this.beforeAll(async function () {
    this.timeout(0);
    circuit = await wasmTester(
      path.join(__dirname, '../../circuits/register/register_aadhaar.circom'),
      {
        verbose: true,
        logOutput: true,
        include: ['node_modules'],
      }
    );
  });

  it('should compile and load the circuit', async function () {
    this.timeout(0);
    expect(circuit).to.not.be.undefined;
  });
  it('should pass constrain check for circuit with Sha256RSA signature', async function () {
    this.timeout(0);
    const { inputs } = prepareTestData();
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);
  });
  it('should pass constrain and output correct nullifier and commitment', async function () {
    this.timeout(0);
    const { inputs, nullifier, commitment } = prepareTestData();
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);

    const out = await circuit.getOutput(w, ['nullifier', 'commitment']);
    assert(BigInt(out.nullifier) === nullifier);
    assert(BigInt(out.commitment) === commitment);
  });
});
