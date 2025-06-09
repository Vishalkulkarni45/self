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
import { packBytesAndPoseidon } from '../../../common/src/utils/hash';
import {  poseidon14, poseidon2 } from 'poseidon-lite';
import { packBytes } from '../../../common/src/utils/bytes';
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

let QRData: string = testQRData;

//Converts 12 selctor to single field
function selectorToField(bits: number[]): number {
  if (bits.length !== 12) throw new Error('Input must be 12 bits');
  let result = 0;
  for (let i = 0; i < 12; i++) {
    if (bits[i]) {
      result += 1 << i;
    }
  }
  return result;
}

function prepareTestData() {
  const qrDataBytes = convertBigIntToByteArray(BigInt(QRData));
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

  const yob = '1984';
  const mob = '1';
  const dob = '1';

  const paddedName = 'Sumit Kumar'
    .padEnd(62, '\0')
    .split('')
    .map((char) => char.charCodeAt(0));
  const name = packBytes(paddedName);

  const qrHash = packBytesAndPoseidon(Array.from(qrDataPadded));
  const photo = extractPhoto(Array.from(qrDataPadded), qrDataPaddedLen);
  const photoHash = packBytesAndPoseidon(photo.bytes.map(Number));
  const commitment = poseidon14([
    BigInt(6),
    BigInt(1234),
    qrHash,
    BigInt(77),
    BigInt(yob),
    BigInt(mob),
    BigInt(dob),
    name[0],
    name[1],
    BigInt(2697),
    BigInt(110051),
    BigInt(452723500356),
    BigInt(1234),
    BigInt(photoHash),
  ]);

  const tree: any = new LeanIMT((a, b) => poseidon2([a, b]), []);
  tree.insert(BigInt(commitment));

  const nameAndDob_smt = new SMT(poseidon2, true);
  nameAndDob_smt.import(nameAndDobAadhaarjson);

  const nameAndYob_smt = new SMT(poseidon2, true);
  nameAndYob_smt.import(nameAndYobAadhaarjson);

  const index = findIndexInTree(tree, commitment);
  const {
    siblings,
    path: merkle_path,
    leaf_depth,
  } = generateMerkleProof(tree, index, COMMITMENT_TREE_DEPTH);

  const namedob_leaf = getNameDobLeafAadhaar('Sumit Kumar', yob, mob, dob);
  const nameyob_leaf = getNameYobLeafAahaar('Sumit Kumar', yob);

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
    attestation_id: '6',
    secret: '1234',
    qrDataHash: qrHash,
    gender: '77',
    yob,
    mob,
    dob,
    name: formatInput(name.slice(0, 2)),
    aadhaar_last_4digits: '2697',
    pincode: '110051',
    state: '452723500356',
    ph_no_last_4digits: '1234',
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

    inputs.selector = formatInput(selectorToField([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))[0];
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);

    const outputs = await circuit.getOutput(w, [
      'reveal_gender',
      'reveal_yob',
      'reveal_mob',
      'reveal_dob',
      'reveal_name[2]',
      'reveal_aadhaar_last_4digits',
      'reveal_pincode',
      'reveal_ph_no_last_4digits',
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
    const sel_bits = [0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1];

    inputs.selector = formatInput(selectorToField(sel_bits))[0];
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);

    const outputs = await circuit.getOutput(w, [
      'reveal_gender',
      'reveal_yob',
      'reveal_mob',
      'reveal_dob',
      'reveal_name[2]',
      'reveal_aadhaar_last_4digits',
      'reveal_pincode',
      'reveal_state',
      'reveal_ph_no_last_4digits',
      'reveal_photoHash',
      'reveal_ofac_name_dob',
      'reveal_ofac_name_yob',
    ]);
    assert(BigInt(outputs.reveal_yob) === BigInt(1984), 'YOB should be 1984');
    assert(BigInt(outputs.reveal_mob) === BigInt(1), 'MOB should be 1');
    assert(BigInt(outputs.reveal_dob) === BigInt(1), 'DOB should be 1');
    assert(BigInt(outputs.reveal_ofac_name_yob) === BigInt(1), 'OFAC Name YOB should be 1');

    let i = 0;
    let j = 0;
    const outputKeys = Object.keys(outputs);
    while (i < outputKeys.length) {
      if (sel_bits[j] == 0) {
        if (i == 4) {
          assert(BigInt(outputs[outputKeys[i]]) === BigInt(0), `${outputKeys[i]} should be zero`);
          assert(
            BigInt(outputs[outputKeys[i + 1]]) === BigInt(0),
            `${outputKeys[i]} should be zero`
          );
          i += 2;
        } else {
          assert(BigInt(outputs[outputKeys[i]]) === BigInt(0), `${outputKeys[i]} should be zero`);
          i++;
        }
      } else {
        i++;
      }
      j++;
    }
  });
});
