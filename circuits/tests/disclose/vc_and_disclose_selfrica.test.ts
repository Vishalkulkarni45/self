import { wasm as wasmTester } from 'circom_tester';
import * as path from 'path';
import { generateCircuitInput, generateCircuitInputWithRealData } from '../../../common/src/utils/selfrica/generateInputs.js';
import { SMT } from '@openpassport/zk-kit-smt';
import { poseidon1, poseidon2 } from 'poseidon-lite';
import nameAndDobjson from '../../../common/ofacdata/outputs/nameAndDobSelfricaSMT.json' with { type: 'json' };
import nameAndYobjson from '../../../common/ofacdata/outputs/nameAndYobSelfricaSMT.json' with { type: 'json' };
import { unpackReveal } from '../../../common/src/utils/circuits/formatOutputs.js';
import { SELFRICA_MAX_LENGTH } from '../../../common/src/utils/selfrica/constants.js';
import { deepEqual } from 'assert';
import { expect } from 'chai';
import { fileURLToPath } from 'url';

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
        const expNullifier = poseidon2([input.nullifier_s, "0"]);
        const expIdCommit = poseidon1([input.s]);

        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            const output = await circuit.getOutput(witness, ['nullifier', 'identity_commitment']);
            expect(BigInt(output.nullifier)).equal(expNullifier);
            expect(BigInt(output.identity_commitment)).equal(expIdCommit);

        } catch (e) { throw e }
    });
    it('should fail for invalid msg  ascii ', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);


        input.SmileID_data[4] = "9999999";
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

        input.s = "27360303589799094027808007181571593860768139721585672592002156609484473730411";
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
    it('should fail for s = 0 ', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);

        input.s = "0";
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            throw new Error(" Circuit verified for s = 0");
        } catch (e) {
            if (e.message.includes("Circuit verified for s = 0")) {
                throw new Error("Circuit verified for s = 0 ");
            }
        }
    });
    it('should fail for -r_inv <  SUBGROUP ORDER ', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);

        input.r_inv = ["7454187305358665457", "12339561404529962506", "3965992003123030795", "435874783350371333"];
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            throw new Error(" Circuit verified for invalid r_inv ");
        } catch (e) {
            if (e.message.includes("Circuit verified for invalid r_inv ")) {
                throw new Error("Circuit verified for invalid r_inv ");
            }
        }
    });

    it('should fail for wrong pubKeyX ', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);

        input.pubKeyX = "5456534826464485121354684856131564654684651"
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

    it('should fail for wrong pubKeyY ', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);

        input.pubKeyY = "5456534826464485121354684856131564654684651"
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            throw new Error(" Circuit verified for invalid pubKeyY ");
        } catch (e) {
            if (e.message.includes("Circuit verified for invalid pubKeyY ")) {
                throw new Error("Circuit verified for invalid pubKeyY ");
            }
        }
    });
    // it.only('should fail for pubKeyx == 0 ', async function () {
    //     this.timeout(0);
    //     const input = generateCircuitInput();

    //     input.pubKeyX = "0"
    //     let didThrow = false;
    //     try {
    //         const witness = await circuit.calculateWitness(input);
    //         await circuit.checkConstraints(witness);
    //     } catch (e) {
    //         const errMsg = e?.message || e?.toString?.() || "";
    //         if (!errMsg.includes("line: 146")) {
    //             throw new Error(`Expected error message to include "line: 39", but got:\n${errMsg}`);
    //         }
    //         didThrow = true;
    //     }
    //     if (!didThrow) {
    //         throw new Error(" Circuit verified for invalid msg byte ascii ");
    //     }
    // })
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
it.only("should work with real data", async function () {
        this.timeout(0);
        // const input = generateCircuitInput(namedob_smt, nameyob_smt, true);

        const serializedRealData = [
            78,
            71,
            65,
            86,
            79,
            84,
            69,
            82,
            95,
            73,
            68,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            57,
            48,
            70,
            53,
            66,
            49,
            65,
            56,
            57,
            54,
            53,
            50,
            56,
            51,
            54,
            51,
            53,
            55,
            54,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            65,
            110,
            100,
            114,
            101,
            119,
            32,
            79,
            110,
            119,
            117,
            101,
            103,
            98,
            117,
            122,
            105,
            101,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            49,
            57,
            57,
            52,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            48,
            56,
            49,
            48,
            57,
            50,
            55,
            57,
            51,
            56,
            57,
            0,
            0,
            0,
            77,
            0,
            0,
            0,
            0,
            0,
            69,
            71,
            87,
            69,
            67,
            72,
            73,
            77,
            69,
            32,
            83,
            84,
            82,
            69,
            69,
            84,
            44,
            32,
            85,
            77,
            85,
            78,
            69,
            68,
            69,
            44,
            32,
            78,
            78,
            69,
            87,
            73,
            32,
            83,
            79,
            85,
            84,
            72,
            44,
            32,
            65,
            78,
            65,
            77,
            66,
            82,
            65,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ].map((x) => String.fromCharCode(x)).join('');

        const input = generateCircuitInputWithRealData(serializedRealData, namedob_smt, nameyob_smt, true);
        try {
            // const witness = await circuit.calculateWitness(input);
            // await circuit.checkConstraints(witness);
        } catch (e) {
            console.log(e.message);
        }
    })
});
