import { wasm as wasmTester } from 'circom_tester';
import * as path from 'path';


function makeInput({
    disclose_sel = Array.from({ length: 298 }, () => (Math.floor(Math.random() * 2)).toString()),

    smileData = smiledata,
    s = "630037470879847701531609472542609422023135651243206071524269210093213685328",
    r_inv = [
        "4143620579060054611",
        "8060624601953140490",
        "11954084563919738676",
        "373078728474647234"
    ],
} = {}) {
    return {
        SmileID_data: smileData,
        disclose_sel,
        s,
        Tx: "7134949030369245611098341356089261752084236119341587288220577651919838782737",
        Ty: "16290264981912618299876954392625697366383580113869408488564063660349257812652",
        pubKeyX: "8340205584289499356632824273164643272534879542102350781612931945544420616740",
        pubKeyY: "9254805840148540323662821564096842980317301284978427129105934150012998266827",
        r_inv,
    };
}

describe('selfricaDisclose', () => {
    let circuit: any;

    before(async function () {
        this.timeout(0);
        circuit = await wasmTester(
            path.join(__dirname, `../../circuits/tests/utils/vcDiscloseSelfrica.circom`),
            { include: ['node_modules'] }
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

const smiledata = [
    "100",
    "26",
    "113",
    "56",
    "70",
    "44",
    "97",
    "40",
    "87",
    "2",
    "50",
    "11",
    "111",
    "5",
    "37",
    "125",
    "12",
    "123",
    "78",
    "44",
    "0",
    "15",
    "78",
    "105",
    "20",
    "56",
    "28",
    "61",
    "79",
    "1",
    "50",
    "14",
    "58",
    "115",
    "93",
    "81",
    "45",
    "101",
    "32",
    "94",
    "109",
    "124",
    "5",
    "34",
    "94",
    "37",
    "90",
    "121",
    "75",
    "105",
    "88",
    "89",
    "50",
    "82",
    "49",
    "84",
    "109",
    "53",
    "99",
    "20",
    "64",
    "0",
    "3",
    "101",
    "34",
    "5",
    "125",
    "11",
    "35",
    "18",
    "22",
    "68",
    "92",
    "7",
    "44",
    "117",
    "21",
    "104",
    "46",
    "48",
    "103",
    "122",
    "99",
    "107",
    "114",
    "2",
    "17",
    "19",
    "7",
    "48",
    "19",
    "48",
    "85",
    "118",
    "83",
    "40",
    "61",
    "7",
    "68",
    "88",
    "87",
    "4",
    "96",
    "106",
    "47",
    "85",
    "25",
    "111",
    "73",
    "109",
    "62",
    "63",
    "108",
    "127",
    "12",
    "77",
    "74",
    "7",
    "10",
    "86",
    "84",
    "32",
    "56",
    "42",
    "22",
    "5",
    "41",
    "14",
    "90",
    "105",
    "26",
    "118",
    "38",
    "104",
    "73",
    "97",
    "94",
    "61",
    "108",
    "72",
    "65",
    "78",
    "113",
    "20",
    "36",
    "17",
    "57",
    "89",
    "125",
    "88",
    "117",
    "37",
    "98",
    "45",
    "43",
    "16",
    "50",
    "28",
    "18",
    "40",
    "123",
    "53",
    "120",
    "111",
    "28",
    "125",
    "85",
    "120",
    "52",
    "18",
    "66",
    "84",
    "21",
    "12",
    "27",
    "1",
    "39",
    "96",
    "29",
    "98",
    "91",
    "2",
    "2",
    "0",
    "66",
    "77",
    "15",
    "7",
    "69",
    "84",
    "103",
    "27",
    "27",
    "93",
    "15",
    "78",
    "77",
    "93",
    "79",
    "127",
    "5",
    "32",
    "26",
    "100",
    "89",
    "108",
    "100",
    "124",
    "60",
    "42",
    "9",
    "80",
    "109",
    "14",
    "80",
    "114",
    "69",
    "7",
    "6",
    "76",
    "43",
    "61",
    "63",
    "110",
    "26",
    "31",
    "49",
    "37",
    "52",
    "111",
    "9",
    "49",
    "25",
    "73",
    "65",
    "86",
    "30",
    "2",
    "42",
    "96",
    "16",
    "120",
    "22",
    "97",
    "60",
    "17",
    "65",
    "4",
    "108",
    "67",
    "5",
    "76",
    "42",
    "121",
    "11",
    "50",
    "0",
    "37",
    "95",
    "124",
    "23",
    "12",
    "38",
    "36",
    "51",
    "26",
    "116",
    "118",
    "40",
    "77",
    "35",
    "109",
    "48",
    "54",
    "47",
    "78",
    "115",
    "96",
    "18",
    "68",
    "78",
    "62",
    "121",
    "54",
    "53",
    "103",
    "47",
    "11",
    "127",
    "2",
    "118",
    "60",
    "0",
    "125",
    "20",
    "44",
    "88",
    "9"
]