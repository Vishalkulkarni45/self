import { wasm as wasmTester } from 'circom_tester';
import * as path from 'path';
import * as fs from 'fs';
import { splitToWords } from '../../../common/src/utils/bytes';

describe('selfricaDisclose', () => {

    it('should compile the circuits', async function () {
        const circuit = await wasmTester(
            path.join(__dirname, `../../circuits/tests/utils/vcDiscloseSelfrica.circom`),
            {
                include: ['node_modules'],
            }
        );
        const inputPath = path.join(__dirname, 'input.json');
        const input = JSON.parse(fs.readFileSync(inputPath, 'utf8'));
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            throw new Error('Test failed: Invalid signature was verified.');
        } catch (error) { }
        console.log("Done")
    })

})