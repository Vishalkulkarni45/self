import { expect } from 'chai';
import { wasm as wasmTester } from 'circom_tester';
import path from 'path';

import { sha256Pad } from '@zk-email/helpers/dist/sha-utils';
import {
  bufferToHex,
  Uint8ArrayToCharArray,
} from '@zk-email/helpers/dist/binary-format';
import {
  convertBigIntToByteArray,
  decompressByteArray,
  splitToWords,
  extractPhoto,
} from '@anon-aadhaar/core';

import fs from 'fs';
import crypto from 'crypto';
import assert from 'assert';
import { testQRData } from '../assets/dataInput.json';
import { customHasher, packBytesAndPoseidon } from '../../../common/src/utils/hash';
import { stringToAsciiArray } from '../utils/aadhaar/utils';
import { generateTestData, testCustomData } from '../utils/aadhaar/generateTestData';
import { formatInput } from '../../../common/src/utils/circuits/generateInputs';


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

    const yob = '1984';
  const mob = '01';
  const dob = '01';

  const nullifierArgs = [77, ...stringToAsciiArray(yob), ...stringToAsciiArray(mob), ...stringToAsciiArray(dob), ...paddedName, ...stringToAsciiArray('2697')];
  const nullifier = customHasher(nullifierArgs.map(String));

  const qrHash = packBytesAndPoseidon(Array.from(qrDataPadded));
  const photo = extractPhoto(Array.from(qrDataPadded), qrDataPaddedLen);
  const photoHash = packBytesAndPoseidon(photo.bytes.map(Number));

  const commitmentInputs = [3 , 1234, qrHash, ...nullifierArgs, ...stringToAsciiArray('110051'), ...stringToAsciiArray('Delhi'.padEnd(31, '\0')), ...stringToAsciiArray('1234'), photoHash];
  assert(commitmentInputs.length === 120, 'Commitment inputs length should be 120');
  const commitment = customHasher(commitmentInputs.map(String));

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
    assert(BigInt(out.nullifier) === BigInt(nullifier));
    assert(BigInt(out.commitment) === BigInt(commitment));
  });

  it('should not verify the signature of created from different key', async function () {
    this.timeout(0);
    const { inputs } = prepareTestData();
    const newTestData = generateTestData({ data: testCustomData });
    const QRDataBytes = convertBigIntToByteArray(BigInt(newTestData.testQRData));
    const decodedData = decompressByteArray(QRDataBytes);

    const signatureBytes = decodedData.slice(decodedData.length - 256, decodedData.length);
    const newSignature = BigInt('0x' + bufferToHex(Buffer.from(signatureBytes)).toString());
    inputs.signature = formatInput(newSignature);

    const w = await circuit.calculateWitness(inputs);

    try {
      await circuit.checkConstraints(w);
    } catch (error) {
      expect(error).to.exist;
    }
  });


  it('should fail when qrdata is tampered', async function () {
    this.timeout(0);
     const { inputs } = prepareTestData();

    const newTestData = generateTestData({ data: testCustomData,  gender: 'F' });
    const QRDataBytes = convertBigIntToByteArray(BigInt(newTestData.testQRData));
    const decodedData = decompressByteArray(QRDataBytes);

    const signedData = decodedData.slice(0, decodedData.length - 256);

    const [qrDataPadded, qrDataPaddedLen] = sha256Pad(signedData, 512 * 3);

    inputs.qrDataPadded = Uint8ArrayToCharArray(qrDataPadded);
    inputs.qrDataPaddedLength = qrDataPaddedLen;

    const w = await circuit.calculateWitness(inputs);

    try {
      await circuit.checkConstraints(w);
    } catch (error) {
      expect(error).to.exist;
    }
  });

  it('should return different commitment when secret is tampered', async function () {
    this.timeout(0);
    const { inputs, commitment } = prepareTestData();
    inputs.secret = '1235';
    const w = await circuit.calculateWitness(inputs);

    const out = await circuit.getOutput(w, ['commitment']);
    assert(BigInt(out.commitment) !== BigInt(commitment));
  });

});
