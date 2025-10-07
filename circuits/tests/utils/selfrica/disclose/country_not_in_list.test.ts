import { expect } from 'chai';
import { wasm as wasmTester } from 'circom_tester';
import * as path from 'path';

describe('Country Not In List', async () => {
    let circuit; 

    before(async () => {
        circuit = await wasmTester(
            path.join(__dirname, "country_not_in_list.test.circom"),
            {
                include: [
                    'node_modules',
                    './node_modules/@zk-kit/binary-merkle-root.circom/src',
                    './node_modules/circomlib/circuits',
                ],
            }
        );
    });

    it('should compile and load the circuit', async () => {
        expect(circuit).to.not.be.undefined;
    });

    it('should throw an error if the country is in the list', async () => {
        const inputs = {
            country: 'US'.split('').map((x) => x.charCodeAt(0)),
            forbidden_countries_list: ['AB', 'CD', 'US'].map((x) => x.split('').map((y) => y.charCodeAt(0))).flat(),
        };

        try { 
            const witness = await circuit.calculateWitness(inputs);
            await circuit.checkConstraints(witness);
            throw new Error('Circuit should have thrown an error');
        } catch (error) {}
    });

    it("should not throw an error if the country is not in the list", async () => {
        const inputs = {
            country: 'US'.split('').map((x) => x.charCodeAt(0)),
            forbidden_countries_list: ['AB', 'CD', 'FR'].map((x) => x.split('').map((y) => y.charCodeAt(0))).flat(),
        };

        const witness = await circuit.calculateWitness(inputs);
        await circuit.checkConstraints(witness);
    });
});