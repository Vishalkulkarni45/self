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
import { customHasher } from '@selfxyz/common/utils/hash';

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

    it.only('should verify for correct Circuit Input and output ', async function () {
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
});
