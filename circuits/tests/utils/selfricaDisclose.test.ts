import { wasm as wasmTester } from 'circom_tester';
import * as crypto from 'crypto';
import * as path from 'path';
import { splitToWords } from '../../../common/src/utils/bytes';

describe('selfricaDisclose', () => {

    it('should compile the circuits', async function () {
        const circuit = await wasmTester(
            path.join(__dirname, `../../circuits/tests/utils/vcDiscloseSelfrica.circom`),
            {
                include: ['node_modules'],
            }
        );
        const input = {
           r_inv:["7454187305358665460","12339561404529962506","3965992003123030795","435874783350371333"]
        }
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            throw new Error('Test failed: Invalid signature was verified.');
        } catch (error) { }
        console.log("Done")
    })

})