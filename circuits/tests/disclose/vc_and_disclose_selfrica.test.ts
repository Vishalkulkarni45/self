import { wasm as wasmTester } from 'circom_tester';
import * as path from 'path';
import { generateCircuitInput } from '../../../common/src/utils/selfrica/generateInputs';



describe('should verify signature on random inputs', () => {
    let circuit;
    before(async function () {
        this.timeout(0);
        circuit = await wasmTester(
            path.join(__dirname, '../../circuits/disclose/vc_and_disclose_selfrica.circom'),
            {
                verbose: true,
                logOutput: true,
                include: ['node_modules']
            }
        );
    });
    it('should pass', async function () {
        this.timeout(0);
        const input = generateCircuitInput();
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
        } catch (e) { throw e }


    });
});
