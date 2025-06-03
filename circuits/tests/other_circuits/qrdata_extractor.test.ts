import { expect } from 'chai';
import path from 'path';
import { wasm as wasm_tester } from 'circom_tester';
import { testQRData } from '../assets/dataInput.json';
import { sha256Pad } from '@zk-email/helpers/dist/sha-utils';
import { Uint8ArrayToCharArray } from '@zk-email/helpers/dist/binary-format';
import { convertBigIntToByteArray, decompressByteArray, extractPhoto } from '@anon-aadhaar/core';
import { assert } from 'chai';
import { packBytesAndPoseidon } from '../../../common/src/utils/hash';
import { poseidon3 } from 'poseidon-lite';

describe('Aadhaar QR Data Extractor1', function () {
  let circuit: any;
  this.beforeAll(async function () {
    this.timeout(0);
    circuit = await wasm_tester(
      path.join(__dirname, '../../circuits/tests/utils/extractQrData_tester.circom'),
      {
        verbose: true,
        logOutput: true,
        include: [
          'node_modules',
          './node_modules/anon-aadhaar-circuits/src/helpers/constants.circom',
          './node_modules/circomlib/circuits',
        ],
      }
    );
  });

  it('should compile and load the circuit', async function () {
    this.timeout(0);
    expect(circuit).to.not.be.undefined;
  });

  it.only('should extract qr data', async function () {
    const QRDataBytes = convertBigIntToByteArray(BigInt(testQRData));
    const QRDataDecode = decompressByteArray(QRDataBytes);

    const signedData = QRDataDecode.slice(0, QRDataDecode.length - 256);

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

    const witness: any[] = await circuit.calculateWitness({
      data: Uint8ArrayToCharArray(qrDataPadded),
      qrDataPaddedLength: qrDataPaddedLen,
      delimiterIndices: delimiterIndices,
    });

    const out = await circuit.getOutput(witness, [
      'gender',
      'nameHash',
      'dobHash',
      'aadhaar_last_4digits',
    ]);
    await circuit.checkConstraints(witness);

    assert(Number(out.gender) === 77);

    const paddedName = 'Sumit Kumar'
      .padEnd(62, '\0')
      .split('')
      .map((char) => char.charCodeAt(0));

    const expNameHash = BigInt(packBytesAndPoseidon(paddedName));
    assert(BigInt(out.nameHash) === expNameHash);

    const expDobHash = poseidon3(['1984', '1', '1']);
    assert(BigInt(out.dobHash) === expDobHash);

    assert(Number(out.aadhaar_last_4digits) === 2697);
  });
});
