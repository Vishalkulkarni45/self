import { wasm as wasmTester } from 'circom_tester';
import * as path from 'path';
import { generateCircuitInput } from '../../../common/src/utils/selfrica/generateInputs';
import { SMT } from '@openpassport/zk-kit-smt';
import { poseidon2 } from 'poseidon-lite';
import nameAndDobjson from '../../../common/ofacdata/outputs/nameAndDobSelfricaSMT.json';
import nameAndYobjson from '../../../common/ofacdata/outputs/nameAndYobSelfricaSMT.json';

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
                    'node_modules',
                    './node_modules/@zk-kit/binary-merkle-root.circom/src',
                    './node_modules/circomlib/circuits',
                ],
            }
        );
    });
    it('should verify correct Circuit Input', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
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

            throw new Error(" Circuit verified for invalid msg byte ascii ");
        } catch (e) {}
    }); 
    it('should fail for s > 251 bits', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);

        input.s = "27360303589799094027808007181571593860768139721585672592002156609484473730411";
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            throw new Error("Circuit verified for invalid s (s > 251 bits)");
        } catch (e) {}
    }); 
    it('should fail for s = 0 ', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);

        input.s = "0";
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            throw new Error(" Circuit verified for s = 0");
        } catch (e) {}
    }); 
    it('should fail for -r_inv <  SUBGROUP ORDER ', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);

        input.r_inv = ["7454187305358665457", "12339561404529962506", "3965992003123030795", "435874783350371333"];
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            throw new Error(" Circuit verified for invalid msg byte ascii ");
        } catch (e) {}
    }); 

    it('should fail for wrong pubKeyX ', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);

        input.pubKeyX = "5456534826464485121354684856131564654684651"
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            throw new Error(" Circuit verified for invalid msg byte ascii ");
        } catch (e) {}
    }); 

    it('should fail for wrong pubKeyY ', async function () {
        this.timeout(0);
        const input = generateCircuitInput(namedob_smt, nameyob_smt);

        input.pubKeyY = "5456534826464485121354684856131564654684651"
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);

            throw new Error(" Circuit verified for invalid msg byte ascii ");
        } catch (e) {}
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


});
