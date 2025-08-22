import { expect } from 'chai';
import { wasm as wasmTester } from 'circom_tester';
import path from 'path';

import assert from 'assert';
import { formatInput } from '../../../common/src/utils/circuits/generateInputs.js';

import { unpackReveal } from '../../../common/src/utils/circuits/formatOutputs.js';
import { fileURLToPath } from 'url';
import { prepareAadhaarDiscloseTestData } from '@selfxyz/common/utils/aadhaar/mockData';
import { SMT } from '@openpassport/zk-kit-smt';
import { LeanIMT } from '@openpassport/zk-kit-lean-imt';
import { poseidon2 } from 'poseidon-lite';
import nameAndDobAadhaarjson from '../../../common/ofacdata/outputs/nameAndDobAadhaarSMT.json' with { type: 'json' };
import nameAndYobAadhaarjson from '../../../common/ofacdata/outputs/nameAndYobAadhaarSMT.json' with { type: 'json' };


const __dirname = path.dirname(fileURLToPath(import.meta.url));
const privateKeyPath = path.join(__dirname, '../../../node_modules/anon-aadhaar-circuits/assets/testPrivateKey.pem');
const publicKeyPath = path.join(__dirname, '../../../common/src/utils/aadhaar/assets/testPublicKey.pem');

// Create SMTs at module level
const nameAndDob_smt = new SMT(poseidon2, true);
nameAndDob_smt.import(nameAndDobAadhaarjson);

const nameAndYob_smt = new SMT(poseidon2, true);
nameAndYob_smt.import(nameAndYobAadhaarjson);

// Create Merkle tree at module level
const tree: any = new LeanIMT((a, b) => poseidon2([a, b]), []);

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
    const { inputs } = prepareAadhaarDiscloseTestData(privateKeyPath, publicKeyPath, tree, nameAndDob_smt, nameAndYob_smt);
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);
  });

  it('should reveal gender only', async function () {
    this.timeout(0);
    const { inputs } = prepareAadhaarDiscloseTestData(privateKeyPath, publicKeyPath, tree, nameAndDob_smt, nameAndYob_smt);

    const sel_bits = Array(119).fill(0);
    sel_bits[0] = 1;
    inputs.selector = formatInput(selectorToField(sel_bits))[0];
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);

    const revealedData = await circuit.getOutput(w, [
      `revealData_packed[4]`,
      'isMinimumAgeValid'
    ]);
    const revealedData_packed = [
                revealedData['revealData_packed[0]'],
                revealedData['revealData_packed[1]'],
                revealedData['revealData_packed[2]'],
                revealedData['revealData_packed[3]'],
            ];
    const revealedDataUnpacked = unpackReveal(revealedData_packed, 'id');

    assert(revealedDataUnpacked[0] === 'M', 'Gender should be Male');
    assert(revealedData.isMinimumAgeValid === '1', 'Age should be greater than minimum age');
    assert(revealedDataUnpacked[118].charCodeAt(0) === Number(inputs.minimumAge[0]), 'Minimum Age should be 1');
  });

  it('should reveal yob, mob, dob, reveal_ofac_name_yob only', async function () {
    this.timeout(0);
    const { inputs } = prepareAadhaarDiscloseTestData(privateKeyPath, publicKeyPath, tree, nameAndDob_smt, nameAndYob_smt);
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
      'reveal_photoHash',
      'isMinimumAgeValid'
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
    assert(revealedData.isMinimumAgeValid === '1', 'Age should be greater than minimum age');
    assert(revealedDataUnpacked[118].charCodeAt(0) === Number(inputs.minimumAge[0]), 'Minimum Age should be 1');
  });

  it('ofac_check_result should be 0 if exists in ofac_name_dob_smt and ofac_name_yob_smt', async function () {
    this.timeout(0);
    const { inputs } = prepareAadhaarDiscloseTestData(privateKeyPath, publicKeyPath, tree, nameAndDob_smt, nameAndYob_smt, 'ABU ABBAS','10-12-1948');
    const sel_bits = Array(119).fill(0);
    sel_bits[117] = 1;
    sel_bits[118] = 1;
    inputs.selector = formatInput(selectorToField(sel_bits))[0];
    inputs.minimumAge = ['100'];
    const w = await circuit.calculateWitness(inputs);
    await circuit.checkConstraints(w);

    const revealedData = await circuit.getOutput(w, [
      `revealData_packed[4]`,
      'isMinimumAgeValid'
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
    assert(revealedData.isMinimumAgeValid === '0');
    assert(revealedDataUnpacked[118].charCodeAt(0) === Number(inputs.minimumAge[0]), 'Minimum Age should be 1');
  });
});
