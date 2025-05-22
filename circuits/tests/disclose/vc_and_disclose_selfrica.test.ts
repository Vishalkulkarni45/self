import { wasm as wasmTester } from 'circom_tester';
import * as path from 'path';


function makeInput({
    disclose_sel = Array.from({ length: 298 }, () => (Math.floor(Math.random() * 2)).toString()),

    smileData = smiledata,
    s = "599377956314884925332252748500668643718490689907140956917148024069808754327",
    r_inv = [
    "15589327464079093472",
    "12406352394983013478",
    "2073144100877832331",
    "4084775207302981"
  ],
} = {}) {
    return {
        SmileID_data: smileData,
        disclose_sel,
        s,
        Tx: "11348112992589078442047131464276217394649034885548413073392616410555026464119",
        Ty: "8017991055953034339458292548071405880589292364363301899606221067920919060104",
        pubKeyX: "6356140599320838240414138869374693627256696394583702301213519557654118406686",
        pubKeyY: "8671447863992353714131015038937072386499033308828420659886210184352411829916",
        r_inv
    };
}

describe('selfricaDisclose', () => {
    let circuit: any;

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

    [
        {
            shouldVerify: true,
            reason: 'should verify with valid input',
            input: () => makeInput(),
        },
        {
            shouldVerify: false,
            reason: 'should fail if disclose_sel contains non-binary values',
            input: () => makeInput({
                disclose_sel: Array.from({ length: 298 }, (_, i) => (i === 0 ? "2" : "1"))
            }),
        },
        {
            shouldVerify: false,
            reason: 'should fail if SmileID_data contains out-of-range ASCII values',
            input: () => {
                const badSmileData = [...smiledata];
                badSmileData[10] = "200";
                return makeInput({ smileData: badSmileData });
            },
        },
        {
            shouldVerify: false,
            reason: 'should fail if s is zero',
            input: () => makeInput({ s: "0" }),
        },
        {
            shouldVerify: false,
            reason: 'should fail if r_inv is not less than scalar_mod',
            input: () => makeInput({
                r_inv: [
                    "7454187305358665457",
                    "12339561404529962506",
                    "3965992003123030795",
                    "435874783350371333"
                ]
            }),
        },
    ].forEach(({ shouldVerify, reason, input }) => {
        it(reason, async function () {
            this.timeout(0);

            // Improved logic: always expect valid inputs to pass, and invalid to throw
            if (shouldVerify) {
                try {
                    const witness = await circuit.calculateWitness(input());
                    await circuit.checkConstraints(witness);
                } catch (err) {
                    throw new Error(`Expected verification to succeed, but failed: ${err}`);
                }
            } else {
                let passed = false;
                try {
                    const witness = await circuit.calculateWitness(input());
                    await circuit.checkConstraints(witness);
                    passed = true;
                } catch (err) {
                    // Expected to fail
                }
                if (passed) {
                    throw new Error('Circuit is underconstrained and accepted invalid input');
                }
            }
        });
    });

    it('should fail if SmileID_data is empty', async function () {
        this.timeout(0);
        const input = makeInput({ smileData: [] });
        let passed = false;
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            passed = true;
        } catch (err) { }
        if (passed) throw new Error('Circuit accepted empty SmileID_data');
    });

    it('should fail if disclose_sel is empty', async function () {
        this.timeout(0);
        const input = makeInput({ disclose_sel: [] });
        let passed = false;
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            passed = true;
        } catch (err) { }
        if (passed) throw new Error('Circuit accepted empty disclose_sel');
    });

    it('should fail if SmileID_data contains negative values', async function () {
        this.timeout(0);
        const badSmileData = [...smiledata];
        badSmileData[5] = "-1";
        const input = makeInput({ smileData: badSmileData });
        let passed = false;
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            passed = true;
        } catch (err) { }
        if (passed) throw new Error('Circuit accepted negative SmileID_data');
    });

    it('should fail if disclose_sel contains negative values', async function () {
        this.timeout(0);
        const badDiscloseSel = Array.from({ length: 298 }, (_, i) => (i === 0 ? "-1" : "1"));
        const input = makeInput({ disclose_sel: badDiscloseSel });
        let passed = false;
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            passed = true;
        } catch (err) { }
        if (passed) throw new Error('Circuit accepted negative disclose_sel');
    });

    it('should fail if r_inv contains negative values', async function () {
        this.timeout(0);
        const badRInv = ["-1", "1", "2", "3"];
        const input = makeInput({ r_inv: badRInv });
        let passed = false;
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            passed = true;
        } catch (err) { }
        if (passed) throw new Error('Circuit accepted negative r_inv');
    });

    it('should fail if s is not a stringified number', async function () {
        this.timeout(0);
        const input = makeInput({ s: "not_a_number" as any });
        let passed = false;
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            passed = true;
        } catch (err) { }
        if (passed) throw new Error('Circuit accepted non-numeric s');
    });

    it('should fail if SmileID_data contains non-numeric strings', async function () {
        this.timeout(0);
        const badSmileData = [...smiledata];
        badSmileData[0] = "abc";
        const input = makeInput({ smileData: badSmileData });
        let passed = false;
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            passed = true;
        } catch (err) { }
        if (passed) throw new Error('Circuit accepted non-numeric SmileID_data');
    });

    it('should fail if disclose_sel contains non-numeric strings', async function () {
        this.timeout(0);
        const badDiscloseSel = Array.from({ length: 298 }, (_, i) => (i === 0 ? "abc" : "1"));
        const input = makeInput({ disclose_sel: badDiscloseSel });
        let passed = false;
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            passed = true;
        } catch (err) { }
        if (passed) throw new Error('Circuit accepted non-numeric disclose_sel');
    });

    it('should fail if r_inv contains non-numeric strings', async function () {
        this.timeout(0);
        const badRInv = ["abc", "1", "2", "3"];
        const input = makeInput({ r_inv: badRInv });
        let passed = false;
        try {
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            passed = true;
        } catch (err) { }
        if (passed) throw new Error('Circuit accepted non-numeric r_inv');
    });

});

const smiledata =[
    "7",
    "21",
    "6",
    "53",
    "116",
    "30",
    "46",
    "68",
    "6",
    "1",
    "119",
    "45",
    "21",
    "46",
    "18",
    "48",
    "51",
    "55",
    "33",
    "126",
    "52",
    "41",
    "91",
    "40",
    "7",
    "109",
    "103",
    "72",
    "103",
    "91",
    "72",
    "71",
    "6",
    "41",
    "123",
    "67",
    "123",
    "108",
    "91",
    "105",
    "105",
    "40",
    "38",
    "37",
    "99",
    "30",
    "100",
    "52",
    "81",
    "101",
    "109",
    "121",
    "32",
    "54",
    "3",
    "122",
    "110",
    "126",
    "63",
    "0",
    "85",
    "49",
    "29",
    "56",
    "37",
    "12",
    "101",
    "29",
    "53",
    "114",
    "58",
    "123",
    "115",
    "9",
    "14",
    "100",
    "43",
    "63",
    "108",
    "11",
    "28",
    "0",
    "66",
    "70",
    "119",
    "90",
    "81",
    "16",
    "17",
    "77",
    "16",
    "62",
    "23",
    "53",
    "59",
    "91",
    "79",
    "40",
    "43",
    "27",
    "117",
    "42",
    "35",
    "59",
    "89",
    "103",
    "37",
    "47",
    "12",
    "121",
    "78",
    "54",
    "113",
    "19",
    "21",
    "2",
    "117",
    "43",
    "124",
    "107",
    "67",
    "51",
    "49",
    "118",
    "40",
    "70",
    "11",
    "94",
    "48",
    "115",
    "32",
    "2",
    "96",
    "46",
    "25",
    "97",
    "0",
    "68",
    "15",
    "1",
    "27",
    "82",
    "119",
    "18",
    "121",
    "24",
    "122",
    "75",
    "90",
    "17",
    "78",
    "40",
    "39",
    "103",
    "26",
    "24",
    "102",
    "95",
    "43",
    "79",
    "64",
    "10",
    "112",
    "28",
    "6",
    "78",
    "10",
    "118",
    "39",
    "123",
    "42",
    "99",
    "12",
    "44",
    "86",
    "71",
    "97",
    "123",
    "88",
    "43",
    "45",
    "86",
    "85",
    "119",
    "73",
    "48",
    "11",
    "71",
    "40",
    "30",
    "82",
    "48",
    "34",
    "72",
    "79",
    "68",
    "50",
    "90",
    "24",
    "11",
    "91",
    "30",
    "40",
    "1",
    "17",
    "13",
    "125",
    "5",
    "49",
    "66",
    "5",
    "28",
    "100",
    "107",
    "13",
    "110",
    "91",
    "6",
    "7",
    "53",
    "70",
    "102",
    "118",
    "9",
    "84",
    "14",
    "85",
    "73",
    "48",
    "98",
    "39",
    "42",
    "65",
    "118",
    "123",
    "60",
    "36",
    "20",
    "83",
    "62",
    "89",
    "59",
    "67",
    "127",
    "14",
    "5",
    "45",
    "90",
    "51",
    "116",
    "89",
    "67",
    "44",
    "48",
    "84",
    "115",
    "87",
    "34",
    "39",
    "51",
    "76",
    "113",
    "84",
    "77",
    "46",
    "55",
    "27",
    "34",
    "18",
    "93",
    "10",
    "18",
    "1",
    "28",
    "70",
    "105",
    "121",
    "33",
    "62",
    "21",
    "70",
    "14",
    "33",
    "12",
    "100",
    "100",
    "45",
    "35",
    "65",
    "74",
    "75",
    "77",
    "1",
    "60",
    "72",
    "4",
    "85",
    "1"
  ]