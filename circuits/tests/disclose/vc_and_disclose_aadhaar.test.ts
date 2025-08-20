import { expect } from 'chai';
import { wasm as wasmTester } from 'circom_tester';
import path from 'path';

import { sha256Pad } from '@zk-email/helpers/dist/sha-utils.js';
import {
  convertBigIntToByteArray,
  decompressByteArray,
  extractPhoto,
} from '@anon-aadhaar/core';

import assert from 'assert';
import jsonData from '../assets/dataInput.json' with { type: 'json' };
import { packBytesAndPoseidon } from '../../../common/src/utils/hash.js';
import { poseidon2, poseidon5 } from 'poseidon-lite';
import { LeanIMT } from '@openpassport/zk-kit-lean-imt';
import { findIndexInTree, formatInput } from '../../../common/src/utils/circuits/generateInputs.js';
import {
  generateMerkleProof,
  generateSMTProof,
  getNameDobLeafAadhaar,
  getNameYobLeafAahaar,
} from '../../../common/src/utils/trees.js';
import { COMMITMENT_TREE_DEPTH } from '../../../common/src/constants/constants.js';
import nameAndDobAadhaarjson from '../../../common/ofacdata/outputs/nameAndDobAadhaarSMT.json' with { type: 'json' };
import nameAndYobAadhaarjson from '../../../common/ofacdata/outputs/nameAndYobAadhaarSMT.json' with { type: 'json' };
import { SMT } from '@openpassport/zk-kit-smt';
import { stringToAsciiArray } from '../utils/aadhaar/utils.js';
import { generateTestData, testCustomData } from '../utils/aadhaar/generateTestData.js';
import { unpackReveal } from '../../../common/src/utils/circuits/formatOutputs.js';
import { fileURLToPath } from 'url';

const { testQRData } = jsonData;

const __dirname = path.dirname(fileURLToPath(import.meta.url));

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

  const [dob, mob, yob] = dateOfBirth.split('-');

  const paddedName = name
    .padEnd(62, '\0')
    .split('')
    .map((char) => char.charCodeAt(0));

  const qrHash = packBytesAndPoseidon(Array.from(qrDataPadded));
  const photo = extractPhoto(Array.from(qrDataPadded), qrDataPaddedLen);
  const photoHash = packBytesAndPoseidon(photo.bytes.map(Number));

  const nullifierArgs = [77, ...stringToAsciiArray(yob), ...stringToAsciiArray(mob), ...stringToAsciiArray(dob), ...paddedName, ...stringToAsciiArray('2697')];
  const nullifier = packBytesAndPoseidon(nullifierArgs);


  const packedCommitmentArgs = [3, ...stringToAsciiArray('110051'), ...stringToAsciiArray('Delhi'.padEnd(31, '\0')), ...stringToAsciiArray('1234')];
  const packedCommitment = packBytesAndPoseidon(packedCommitmentArgs);

  const commitment = poseidon5([BigInt(1234), BigInt(qrHash), BigInt(nullifier), BigInt(packedCommitment), BigInt(photoHash)]);

  const tree: any = new LeanIMT((a, b) => poseidon2([a, b]), []);
  tree.insert(BigInt(commitment));

  const nameAndDob_smt = new SMT(poseidon2, true);
  nameAndDob_smt.import(nameAndDobAadhaarjson);

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
        include: ['../node_modules', '../node_modules/circomlib/circuits'],
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

    const revealedData = await circuit.getOutput(w, [
      `revealData_packed[4]`
    ]);
    const revealedData_packed = [
                revealedData['revealData_packed[0]'],
                revealedData['revealData_packed[1]'],
                revealedData['revealData_packed[2]'],
                revealedData['revealData_packed[3]'],
            ];
    const revealedDataUnpacked = unpackReveal(revealedData_packed, 'id');

    assert(revealedDataUnpacked[0] === 'M', 'Gender should be Male');

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

    const revealedData = await circuit.getOutput(w, [
      `revealData_packed[4]`,
      'reveal_photoHash'
    ]);
    const revealedData_packed = [
                revealedData['revealData_packed[0]'],
                revealedData['revealData_packed[1]'],
                revealedData['revealData_packed[2]'],
                revealedData['revealData_packed[3]'],
            ];
    const revealedDataUnpacked = unpackReveal(revealedData_packed, 'id');

    assert(revealedDataUnpacked[1] === '1', 'YOB should be 1');
    assert(revealedDataUnpacked[2] === '9', 'YOB should be 9');
    assert(revealedDataUnpacked[3] === '8', 'YOB should be 8');
    assert(revealedDataUnpacked[4] === '4', 'YOB should be 4');

    assert(revealedDataUnpacked[5] === '0', 'MOB should be 1');
    assert(revealedDataUnpacked[6] === '1', 'MOB should be 2');

    assert(revealedDataUnpacked[7] === '0', 'DOB should be 1');
    assert(revealedDataUnpacked[8] === '1', 'DOB should be 1');

    assert(revealedDataUnpacked[117].charCodeAt(0) === 1, 'OFAC Name YOB should be 1 (not in OFAC list)');

    for (let i = 9; i < 116; i++) {
      assert(revealedDataUnpacked[i] === '\0', `Output ${i} should be null character`);
    }
    assert(revealedData.reveal_photoHash === '0', 'Photo Hash should be 0');
  });

  it('ofac_check_result should be 0 if exists in ofac_name_dob_smt and ofac_name_yob_smt', async function () {
    this.timeout(0);
    const { inputs } = prepareTestData('ABU ABBAS','10-12-1948');
    const sel_bits = Array(119).fill(0);
    sel_bits[117] = 1;
    sel_bits[118] = 1;
    inputs.selector = formatInput(selectorToField(sel_bits))[0];
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);

    const revealedData = await circuit.getOutput(w, [
      `revealData_packed[4]`,
    ]);

    const revealedData_packed = [
                revealedData['revealData_packed[0]'],
                revealedData['revealData_packed[1]'],
                revealedData['revealData_packed[2]'],
                revealedData['revealData_packed[3]'],
            ];
    const revealedDataUnpacked = unpackReveal(revealedData_packed, 'id');

    for (let i = 0; i < 115; i++) {
      assert(revealedDataUnpacked[i] === '\0', `Output ${i} should be null character`);
    }

    assert(revealedDataUnpacked[117].charCodeAt(0) === 0, 'OFAC Name YOB should be 0 (in OFAC list)');
    assert(revealedDataUnpacked[116].charCodeAt(0) === 0, 'OFAC Name DOB should be 0 (in OFAC list)');
  });
});
