import { expect } from 'chai';
import { wasm as wasmTester } from 'circom_tester';
import path from 'path';

import { sha256Pad } from '@zk-email/helpers/dist/sha-utils.js';
import {
  bufferToHex,
  Uint8ArrayToCharArray,
} from '@zk-email/helpers/dist/binary-format.js';
import {
  convertBigIntToByteArray,
  decompressByteArray,
  splitToWords,
  extractPhoto,
} from '@anon-aadhaar/core';

import fs from 'fs';
import crypto from 'crypto';
import assert from 'assert';
import jsonData from '../assets/dataInput.json' with { type: 'json' };
import { customHasher, packBytesAndPoseidon } from '../../../common/src/utils/hash.js';
import { poseidon5 } from 'poseidon-lite';
import { stringToAsciiArray } from '../utils/aadhaar/utils.js';
import { generateTestData, testCustomData } from '../utils/aadhaar/generateTestData.js';
import { formatInput } from '../../../common/src/utils/circuits/generateInputs.js';
import { fileURLToPath } from 'url';

const { testQRData } = jsonData;

let QRData: string = testQRData;

const __dirname = path.dirname(fileURLToPath(import.meta.url));


function prepareTestData(name?: string, dateOfBirth?: string, gender?: string, pincode?: string, state?: string) {

  let qrDataBytes: any;
  if(name || dateOfBirth || gender || pincode || state){
    const newTestData = generateTestData({ data: testCustomData, name: name , dob: dateOfBirth, gender: gender, pincode: pincode, state: state});
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

  const pkPem = fs.readFileSync(path.join(__dirname, '../assets/testPublicKey.pem'));
  const pk = crypto.createPublicKey(pkPem);

  const pubKey = BigInt(
    '0x' + bufferToHex(Buffer.from(pk.export({ format: 'jwk' }).n as string, 'base64url'))
  );

  const paddedName = name
    .padEnd(62, '\0')
    .split('')
    .map((char) => char.charCodeAt(0));

  const [dob, mob, yob] = dateOfBirth.split('-');

  const nullifierArgs = [stringToAsciiArray(gender)[0], ...stringToAsciiArray(yob), ...stringToAsciiArray(mob), ...stringToAsciiArray(dob), ...paddedName, ...stringToAsciiArray('2697')];
  const nullifier = packBytesAndPoseidon(nullifierArgs);

  const qrHash = packBytesAndPoseidon(Array.from(qrDataPadded));
  const photo = extractPhoto(Array.from(qrDataPadded), qrDataPaddedLen);
  const photoHash = packBytesAndPoseidon(photo.bytes.map(Number));

  const packedCommitmentArgs = [3, ...stringToAsciiArray(pincode), ...stringToAsciiArray(state.padEnd(31, '\0')), ...stringToAsciiArray('1234')];
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
describe(' REGISTER AADHAAR Circuit Tests', function () {
  let circuit: any;
  this.beforeAll(async function () {
    this.timeout(0);
    circuit = await wasmTester(
      path.join(__dirname, '../../circuits/register/register_aadhaar.circom'),
      {
        verbose: true,
        logOutput: true,
        include: ['../node_modules'],
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
    inputs.signature = splitToWords(newSignature, BigInt(121), BigInt(17));

    try {
      await circuit.calculateWitness(inputs);
      expect.fail('Expected circuit.calculateWitness to throw an error, but it succeeded');
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

    try {
      await circuit.calculateWitness(inputs);
      expect.fail('Expected circuit.calculateWitness to throw an error, but it succeeded');
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

  it('should pass for different qr data', async function () {
    this.timeout(0);
    const { inputs, nullifier, commitment } = prepareTestData('KL RAHUL', '18-04-1992');
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);

    const out = await circuit.getOutput(w, ['nullifier', 'commitment']);
    assert(BigInt(out.nullifier) === BigInt(nullifier));
    assert(BigInt(out.commitment) === BigInt(commitment));

  });

});
