import { expect } from 'chai';
import { wasm as wasmTester } from 'circom_tester';
import path from 'path';

import { sha256Pad } from '@zk-email/helpers/dist/sha-utils';
import {
  convertBigIntToByteArray,
  decompressByteArray,
  extractPhoto,
} from '@anon-aadhaar/core';

import assert from 'assert';
import { testQRData } from '../assets/dataInput.json';
import { customHasher, packBytesAndPoseidon } from '../../../common/src/utils/hash';
import { poseidon2 } from 'poseidon-lite';
import { LeanIMT } from '@openpassport/zk-kit-lean-imt';
import { findIndexInTree, formatInput } from '../../../common/src/utils/circuits/generateInputs';
import {
  generateMerkleProof,
  generateSMTProof,
  getNameDobLeafAadhaar,
  getNameYobLeafAahaar,
} from '../../../common/src/utils/trees';
import { COMMITMENT_TREE_DEPTH } from '../../../common/src/constants/constants';
import nameAndDobAadhaarjson from '../../../common/ofacdata/outputs/nameAndDobSMT.json';
import nameAndYobAadhaarjson from '../../../common/ofacdata/outputs/nameAndYobSMT.json';
import { SMT } from '@openpassport/zk-kit-smt';
import { stringToAsciiArray } from '../utils/aadhaar/utils';
import { generateTestData, testCustomData } from '../utils/aadhaar/generateTestData';

let QRData: string = testQRData;

//Converts 119 selctor to single field
function selectorToField(bits: number[]): bigint {
  if (bits.length !== 119) throw new Error('Input must be 119 bits');
  let result = 0n;
  for (let i = 0; i < 119; i++) {
    if (bits[i]) {
      result += 1n << BigInt(i);
    }
  }
  return result;
}

function prepareTestData(name: string = 'Sumit Kumar', dateOfBirth: string = '01-01-1984') {

  let qrDataBytes: any;

  if(name){
    const newTestData = generateTestData({ data: testCustomData, name: name , dob: dateOfBirth});
    qrDataBytes = convertBigIntToByteArray(BigInt(newTestData.testQRData));
  }else{
    qrDataBytes = convertBigIntToByteArray(BigInt(QRData));
  }

  const decodedData = decompressByteArray(qrDataBytes);
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

  const [dob, mob, yob] = dateOfBirth.split('-');

  console.log('yob',yob);
  console.log('mob',mob);
  console.log('dob',dob);

  const paddedName = name
    .padEnd(62, '\0')
    .split('')
    .map((char) => char.charCodeAt(0));

  const qrHash = packBytesAndPoseidon(Array.from(qrDataPadded));
  const photo = extractPhoto(Array.from(qrDataPadded), qrDataPaddedLen);
  const photoHash = packBytesAndPoseidon(photo.bytes.map(Number));

  const nullifierArgs = [77, ...stringToAsciiArray(yob), ...stringToAsciiArray(mob), ...stringToAsciiArray(dob), ...paddedName, ...stringToAsciiArray('2697')];
  const commitmentInputs = [3 , 1234, qrHash, ...nullifierArgs, ...stringToAsciiArray('110051'), ...stringToAsciiArray('Delhi'.padEnd(31, '\0')), ...stringToAsciiArray('1234'), photoHash];
  const commitment = customHasher(commitmentInputs.map(String));

  const tree: any = new LeanIMT((a, b) => poseidon2([a, b]), []);
  tree.insert(BigInt(commitment));

  const nameAndDob_smt = new SMT(poseidon2, true);
  nameAndDob_smt.import(nameAndDobAadhaarjson);

  console.log('nameAndDob_smt',nameAndDob_smt);

  const nameAndYob_smt = new SMT(poseidon2, true);
  nameAndYob_smt.import(nameAndYobAadhaarjson);

  const index = findIndexInTree(tree, BigInt(commitment));
  const {
    siblings,
    path: merkle_path,
    leaf_depth,
  } = generateMerkleProof(tree, index, COMMITMENT_TREE_DEPTH);

  const namedob_leaf = getNameDobLeafAadhaar(name, yob, mob, dob);
  const nameyob_leaf = getNameYobLeafAahaar(name, yob);

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
    secret: '1234',
    qrDataHash: qrHash,
    gender: '77',
    yob:stringToAsciiArray(yob),
    mob:stringToAsciiArray(mob),
    dob:stringToAsciiArray(dob),
    name: formatInput(paddedName),
    aadhaar_last_4digits: stringToAsciiArray('2697'),
    pincode: stringToAsciiArray('110051'),
    state: stringToAsciiArray('Delhi'.padEnd(31, '\0')),
    ph_no_last_4digits: stringToAsciiArray('1234'),
    photoHash: formatInput(BigInt(photoHash)),
    merkle_root: formatInput(tree.root),
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
  };

  return {
    inputs,
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

  it('should calculate witness and pass constrain check', async function () {
    this.timeout(0);
    const { inputs } = prepareTestData();
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);
  });

  it('should reveal gender only', async function () {
    this.timeout(0);
    const { inputs } = prepareTestData();

    const sel_bits = Array(119).fill(0);
    sel_bits[0] = 1;
    inputs.selector = formatInput(selectorToField(sel_bits))[0];
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);

    const outputs = await circuit.getOutput(w, [
      'reveal_gender',
      'reveal_yob[4]',
      'reveal_mob[2]',
      'reveal_dob[2]',
      'reveal_name[62]',
      'reveal_aadhaar_last_4digits[4]',
      'reveal_pincode[6]',
      'reveal_state[31]',
      'reveal_ph_no_last_4digits[4]',
      'reveal_photoHash',
      'reveal_ofac_name_dob',
      'reveal_ofac_name_yob',
    ]);
    assert(BigInt(outputs.reveal_gender) === BigInt(77), 'Gender should be Male');
    const outputKeys = Object.keys(outputs);
    for (let i = 1; i < outputKeys.length; i++) {
      assert(BigInt(outputs[outputKeys[i]]) === BigInt(0), `${outputKeys[i]} should be zero`);
    }
  });

  it('should reveal yob, mob, dob, reveal_ofac_name_yob only', async function () {
    this.timeout(0);
    const { inputs } = prepareTestData();
    const sel_bits = Array(119).fill(0);
    // year selector
    sel_bits[1] = 1;
    sel_bits[2] = 1;
    sel_bits[3] = 1;
    sel_bits[4] = 1;
    // month selector
    sel_bits[5] = 1;
    sel_bits[6] = 1;
    // day selector
    sel_bits[7] = 1;
    sel_bits[8] = 1;

    // ofac name yob selector
    sel_bits[118] = 1;

    inputs.selector = formatInput(selectorToField(sel_bits))[0];
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);

    const outputs = await circuit.getOutput(w, [
      'reveal_gender',
      'reveal_yob[4]',
      'reveal_mob[2]',
      'reveal_dob[2]',
      'reveal_name[62]',
      'reveal_aadhaar_last_4digits[4]',
      'reveal_pincode[6]',
      'reveal_state[31]',
      'reveal_ph_no_last_4digits[4]',
      'reveal_photoHash',
      'reveal_ofac_name_dob',
      'reveal_ofac_name_yob',
    ]);

    // check if the outputs are correct
    assert(BigInt(outputs['reveal_yob[0]']) === BigInt(1), 'YOB[0] should be 1');
    assert(BigInt(outputs['reveal_yob[1]']) === BigInt(9), 'YOB[1] should be 9');
    assert(BigInt(outputs['reveal_yob[2]']) === BigInt(8), 'YOB[2] should be 8');
    assert(BigInt(outputs['reveal_yob[3]']) === BigInt(4), 'YOB[3] should be 4');

    assert(BigInt(outputs['reveal_mob[0]']) === BigInt(0), 'MOB[0] should be 0');
    assert(BigInt(outputs['reveal_mob[1]']) === BigInt(1), 'MOB[1] should be 1');

    assert(BigInt(outputs['reveal_dob[0]']) === BigInt(0), 'DOB[0] should be 0');
    assert(BigInt(outputs['reveal_dob[1]']) === BigInt(1), 'DOB[1] should be 1');

    assert(BigInt(outputs.reveal_ofac_name_yob) === BigInt(1), 'OFAC Name YOB should be 1');

    // check that all other outputs are zero
    assert(BigInt(outputs.reveal_gender) === 0n, 'reveal_gender should be zero');

    for (let i = 0; i < 62; i++) {
      assert(BigInt(outputs[`reveal_name[${i}]`]) === 0n, `reveal_name[${i}] should be zero`);
    }
    for (let i = 0; i < 4; i++) {
      assert(
        BigInt(outputs[`reveal_aadhaar_last_4digits[${i}]`]) === 0n,
        `reveal_aadhaar_last_4digits[${i}] should be zero`,
      );
    }
    for (let i = 0; i < 6; i++) {
      assert(BigInt(outputs[`reveal_pincode[${i}]`]) === 0n, `reveal_pincode[${i}] should be zero`);
    }
    for (let i = 0; i < 31; i++) {
      assert(BigInt(outputs[`reveal_state[${i}]`]) === 0n, `reveal_state[${i}] should be zero`);
    }
    for (let i = 0; i < 4; i++) {
      assert(
        BigInt(outputs[`reveal_ph_no_last_4digits[${i}]`]) === 0n,
        `reveal_ph_no_last_4digits[${i}] should be zero`,
      );
    }

    assert(BigInt(outputs.reveal_photoHash) === 0n, 'reveal_photoHash should be zero');
    assert(BigInt(outputs.reveal_ofac_name_dob) === 0n, 'reveal_ofac_name_dob should be zero');
  });

  it.only('reveal_ofac_name_dob should be 0 if exists in ofac_name_dob_smt', async function () {
    this.timeout(0);
    const { inputs } = prepareTestData('ABU ABBAS','10-12-1948');
    const sel_bits = Array(119).fill(0);
    sel_bits[117] = 1;
    inputs.selector = formatInput(selectorToField(sel_bits))[0];
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);

    const outputs = await circuit.getOutput(w, [
      'reveal_gender',
      'reveal_yob[4]',
      'reveal_mob[2]',
      'reveal_dob[2]',
      'reveal_name[62]',
      'reveal_aadhaar_last_4digits[4]',
      'reveal_pincode[6]',
      'reveal_state[31]',
      'reveal_ph_no_last_4digits[4]',
      'reveal_photoHash',
      'reveal_ofac_name_dob',
      'reveal_ofac_name_yob',
    ]);

    assert(BigInt(outputs.reveal_ofac_name_dob) === BigInt(0), 'reveal_ofac_name_dob should be 0');

  });
});
