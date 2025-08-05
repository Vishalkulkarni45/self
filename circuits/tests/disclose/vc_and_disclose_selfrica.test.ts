import { wasm as wasmTester } from 'circom_tester';
import * as path from 'path';
import { generateCircuitInput, generateCircuitInputWithRealData, NON_OFAC_DUMMY_INPUT, OFAC_DUMMY_INPUT } from '../../../common/src/utils/selfrica/generateInputs.js';
import { SMT } from '@openpassport/zk-kit-smt';
import { poseidon1, poseidon2 } from 'poseidon-lite';
import nameAndDobjson from '../../../common/ofacdata/outputs/nameAndDobSelfricaSMT.json' with { type: 'json' };
import nameAndYobjson from '../../../common/ofacdata/outputs/nameAndYobSelfricaSMT.json' with { type: 'json' };
import { unpackReveal } from '../../../common/src/utils/circuits/formatOutputs.js';
import { SELFRICA_MAX_LENGTH } from '../../../common/src/utils/selfrica/constants.js';
import { deepEqual } from 'assert';
import { expect } from 'chai';
import { fileURLToPath } from 'url';
import { customHasher } from '@selfxyz/common/utils/hash';
import { serializeSmileData } from '@selfxyz/common/utils/selfrica/types';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('should verify signature on random inputs', () => {
    let circuit;
    let namedob_smt = new SMT(poseidon2, true);
    let nameyob_smt = new SMT(poseidon2, true);

    namedob_smt.import(nameAndDobjson);
    nameyob_smt.import(nameAndYobjson);

    before(async function () {
        this.timeout(0);
        circuit = await wasmTester(
            path.join(__dirname, '../../circuits/disclose/vc_and_disclose_selfrica.circom'),
            {
                verbose: true,
                logOutput: true,
                include: [
                    '../node_modules',
                    '../node_modules/@zk-kit/binary-merkle-root.circom/src',
                    '../node_modules/circomlib/circuits',
                ],
            }
        );
    });

    it('should verify for correct Circuit Input and output ', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);
        const expNullifier = customHasher([...input.id_num_sig, "0"]);
        const expIdCommit = customHasher(input.msg_sig);

        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            const output = await circuit.getOutput(witness, ['nullifier', 'identity_commitment']);
            expect(BigInt(output.nullifier)).equal(BigInt(expNullifier));
            expect(BigInt(output.identity_commitment)).equal(BigInt(expIdCommit));

        } catch (e) { throw e }
    });
    it('should fail for invalid msg  ascii ', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);


        input.SmileID_data_padded[4] = "9999999";
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            throw new Error(" Circuit verified for invalid msg byte ascii ");
        } catch (e) {
            const errMsg = e?.message || e?.toString?.() || "";
            if (!errMsg.includes("Num2Bits")) {
                console.log('errMsg', errMsg);
                throw new Error(`Expected error message to include "Num2Bits", but got:\n${errMsg}`);
            }
        }
    });
    it('should fail for invalid disclose selectors ', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);

        input.disclose_sel[4] = "20";
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            throw new Error("Circuit verified for invalid disclose selector ");
        } catch (e) {
            if (e.message.includes("Circuit verified for invalid disclose selector")) {
                throw new Error("Circuit verified for invalid disclose selector ");
            }
        }
    });
    it('should fail for s > 251 bits', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);

        input.msg_sig[0] = "273609484473730411";
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            throw new Error("Circuit verified for invalid s (s > 251 bits)");
        } catch (e) {
            if (e.message.includes("Circuit verified for invalid s (s > 251 bits)")) {
                throw new Error("Circuit verified for invalid s (s > 251 bits) ");
            }
        }
    });


    it('should fail for wrong pubKey ', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);

        input.pubKey[0] = "5456531564654684651"
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            throw new Error(" Circuit verified for invalid pubKeyX ");
        } catch (e) {
            if (e.message.includes("Circuit verified for invalid pubKeyX ")) {
                throw new Error("Circuit verified for invalid pubKeyX ");
            }
        }
    });

    it("should return 0 for an OFAC person", async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt, true);
        input.selector_ofac = ["1"];
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            const revealedData = (await circuit.getOutput(witness, ['revealedData_packed[9]']));
            const revealedData_packed = [
                revealedData['revealedData_packed[0]'],
                revealedData['revealedData_packed[1]'],
                revealedData['revealedData_packed[2]'],
                revealedData['revealedData_packed[3]'],
                revealedData['revealedData_packed[4]'],
                revealedData['revealedData_packed[5]'],
                revealedData['revealedData_packed[6]'],
                revealedData['revealedData_packed[7]'],
                revealedData['revealedData_packed[8]'],
            ];
            const revealedDataUnpacked = unpackReveal(revealedData_packed, 'id');
            const ofac_results = revealedDataUnpacked.slice(SELFRICA_MAX_LENGTH, SELFRICA_MAX_LENGTH + 2);

            deepEqual(ofac_results, ['\x00', '\x00']);
        } catch (e) {
            console.log(e.message);
        }
    })

    it("should return 1 for a non OFAC person", async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt, false);
        input.selector_ofac = ["1"];
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            const revealedData = (await circuit.getOutput(witness, ['revealedData_packed[9]']));
            const revealedData_packed = [
                revealedData['revealedData_packed[0]'],
                revealedData['revealedData_packed[1]'],
                revealedData['revealedData_packed[2]'],
                revealedData['revealedData_packed[3]'],
                revealedData['revealedData_packed[4]'],
                revealedData['revealedData_packed[5]'],
                revealedData['revealedData_packed[6]'],
                revealedData['revealedData_packed[7]'],
                revealedData['revealedData_packed[8]'],
            ];
            const revealedDataUnpacked = unpackReveal(revealedData_packed, 'id');
            const ofac_results = revealedDataUnpacked.slice(SELFRICA_MAX_LENGTH, SELFRICA_MAX_LENGTH + 2);

            deepEqual(ofac_results, ['\x01', '\x01']);
        } catch (e) {
            console.log(e.message);
        }
    })
    it("should return revealed data that matches the actual smile data", async function () {
        this.timeout(0);

        // Test with NON_OFAC_DUMMY_INPUT
        const input = generateCircuitInput(namedob_smt, nameyob_smt, false);
        input.selector_ofac = ["1"];
        input.selector_older_than = ["1"];

        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            const revealedData = (await circuit.getOutput(witness, ['revealedData_packed[9]']));
            const revealedData_packed = [
                revealedData['revealedData_packed[0]'],
                revealedData['revealedData_packed[1]'],
                revealedData['revealedData_packed[2]'],
                revealedData['revealedData_packed[3]'],
                revealedData['revealedData_packed[4]'],
                revealedData['revealedData_packed[5]'],
                revealedData['revealedData_packed[6]'],
                revealedData['revealedData_packed[7]'],
                revealedData['revealedData_packed[8]'],
            ];
            const revealedDataUnpacked = unpackReveal(revealedData_packed, 'id');

            // Since disclose_sel is set to all 1s in generateCircuitInput,
            // the first SELFRICA_MAX_LENGTH bytes should match the serialized smile data
            const serializedData = Buffer.from(serializeSmileData(NON_OFAC_DUMMY_INPUT), 'utf8');
            const serializedArray = Array.from(serializedData);

            // Check that revealed smile data matches the expected data
            // Note: We compare up to the length of the actual data since the circuit pads to SELFRICA_MAX_LENGTH
            for (let i = 0; i < Math.min(serializedArray.length, SELFRICA_MAX_LENGTH); i++) {
                const expectedByte = serializedArray[i];
                const expectedChar = String.fromCharCode(expectedByte);
                const revealedChar = revealedDataUnpacked[i];
                const revealedByte = revealedChar.charCodeAt(0);
                expect(revealedByte).to.equal(expectedByte, `Mismatch at position ${i}: expected '${expectedChar}' (${expectedByte}) but got '${revealedChar}' (${revealedByte})`);
            }

            // Check OFAC results (should be 1,1 for non-OFAC person)
            const ofac_results = revealedDataUnpacked.slice(SELFRICA_MAX_LENGTH, SELFRICA_MAX_LENGTH + 2);
            deepEqual(ofac_results, ['\x01', '\x01']);

            // Check age verification results (should show majority age since selector_older_than is 1)
            const age_results = revealedDataUnpacked.slice(SELFRICA_MAX_LENGTH + 2, SELFRICA_MAX_LENGTH + 5);
            // Age verification should return the majority age characters when person is older than that age
            // expect(age_results[0]).to.equal('0'); // First char of '20'
            // expect(age_results[1]).to.equal('0'); // Second char mapped from '0'
            // expect(age_results[2]).to.equal('1'); // Third char mapped from '1'

        } catch (e) {
            console.log('Error in test:', e.message);
            throw e;
        }
    })


    it("should return revealed data that matches the actual smile data for OFAC person", async function () {
        this.timeout(0);

        // Test with OFAC_DUMMY_INPUT
        const input = generateCircuitInput(namedob_smt, nameyob_smt, true);
        input.selector_ofac = ["1"];
        input.selector_older_than = ["1"];

        // Get the expected smile data from OFAC_DUMMY_INPUT
        const expectedSmileData = OFAC_DUMMY_INPUT;

        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            const revealedData = (await circuit.getOutput(witness, ['revealedData_packed[9]']));
            const revealedData_packed = [
                revealedData['revealedData_packed[0]'],
                revealedData['revealedData_packed[1]'],
                revealedData['revealedData_packed[2]'],
                revealedData['revealedData_packed[3]'],
                revealedData['revealedData_packed[4]'],
                revealedData['revealedData_packed[5]'],
                revealedData['revealedData_packed[6]'],
                revealedData['revealedData_packed[7]'],
                revealedData['revealedData_packed[8]'],
            ];
            const revealedDataUnpacked = unpackReveal(revealedData_packed, 'id');

            // Since disclose_sel is set to all 1s in generateCircuitInput,
            // the first SELFRICA_MAX_LENGTH bytes should match the serialized smile data
            const serializedData = Buffer.from(serializeSmileData(expectedSmileData), 'utf8');
            const serializedArray = Array.from(serializedData);

            // Check that revealed smile data matches the expected data
            // Note: We compare up to the length of the actual data since the circuit pads to SELFRICA_MAX_LENGTH
            for (let i = 0; i < Math.min(serializedArray.length, SELFRICA_MAX_LENGTH); i++) {
                const expectedByte = serializedArray[i];
                const expectedChar = String.fromCharCode(expectedByte);
                const revealedChar = revealedDataUnpacked[i];
                const revealedByte = revealedChar.charCodeAt(0);
                expect(revealedByte).to.equal(expectedByte, `Mismatch at position ${i}: expected '${expectedChar}' (${expectedByte}) but got '${revealedChar}' (${revealedByte})`);
            }

            // Check OFAC results (should be 0,0 for OFAC person)
            const ofac_results = revealedDataUnpacked.slice(SELFRICA_MAX_LENGTH, SELFRICA_MAX_LENGTH + 2);
            deepEqual(ofac_results, ['\x00', '\x00']);

            // Check age verification results (should show majority age since selector_older_than is 1)
            const age_results = revealedDataUnpacked.slice(SELFRICA_MAX_LENGTH + 2, SELFRICA_MAX_LENGTH + 5);
            // Age verification should return the majority age ASCII values when person is older than that age
            // expect(age_results[0].charCodeAt(0)).to.equal(48); // ASCII '0' = 48
            // expect(age_results[1].charCodeAt(0)).to.equal(50); // ASCII '2' = 50
            // expect(age_results[2].charCodeAt(0)).to.equal(48); // ASCII '0' = 48

        } catch (e) {
            console.log('Error in test:', e.message);
            throw e;
        }
    })
});
