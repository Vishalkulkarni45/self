import { SMT } from "@openpassport/zk-kit-smt";
import { generateSMTProof, getNameDobLeafSelfrica, getNameYobLeafSelfrica } from "../trees.js";
import { SelfricaCircuitInput, serializeSmileData, SmileData } from "./types.js";
import { formatInput } from "../circuits/generateInputs.js";
import { bigintTo64bitLimbs, getEffECDSAArgs, modInv, modulus } from "./ecdsa/utils.js";
import { signECDSA, verifyECDSA, verifyEffECDSA } from "./ecdsa/ecdsa.js";
import { Base8, inCurve, mulPointEscalar, subOrder } from "@zk-kit/baby-jubjub";
import { SELFRICA_DOB_INDEX, SELFRICA_DOB_LENGTH, SELFRICA_FULL_NAME_INDEX, SELFRICA_FULL_NAME_LENGTH, SELFRICA_MAX_LENGTH } from "./constants.js";

export const OFAC_DUMMY_INPUT: SmileData = {
    country: 'KEN',
    idType: 'NATIONAL ID',
    idNumber: '1234567890',
    issuanceDate: '20200101',
    expiryDate: '20250101', //expiry date is 5 years from issuance date
    fullName: 'ABBAS ABU',
    dob: '19481210',
    photoHash: '1234567890',
    phoneNumber: '1234567890',
    document: 'ID',
    gender: 'Male',
    address: '1234567890',
    user_identifier: '1234567890',
    current_date: '20250101',
    majority_age_ASCII: '20',
    selector_older_than: '1',
};

export const NON_OFAC_DUMMY_INPUT: SmileData = {
    country: 'KEN',
    idType: 'NATIONAL ID',
    idNumber: '1234567890',
    issuanceDate: '20200101',
    expiryDate: '20250101',
    fullName: 'John Doe',
    dob: '19900101',
    photoHash: '1234567890',
    phoneNumber: '1234567890',
    document: 'ID',
    gender: 'Male',
    address: '1234567890',
    user_identifier: '1234567890',
    current_date: '20250101',
    majority_age_ASCII: '20',
    selector_older_than: '1',
}

export const generateCircuitInputsOfac = (smileData: SmileData, smt: SMT, proofLevel: number) => {
    const name = smileData.fullName;
    const dob = smileData.dob;
    const yob = smileData.dob.slice(0, 4);

    const nameDobLeaf = getNameDobLeafSelfrica(name, dob);
    const nameYobLeaf = getNameYobLeafSelfrica(name, yob);

    let root, closestleaf, siblings;
    if (proofLevel == 2) {
        ({ root, closestleaf, siblings } = generateSMTProof(smt, nameDobLeaf));
    } else if (proofLevel == 1) {
        ({ root, closestleaf, siblings } = generateSMTProof(smt, nameYobLeaf));
    } else {
        throw new Error('Invalid proof level');
    }

    return {
        smt_root: formatInput(root),
        smt_leaf_key: formatInput(closestleaf),
        smt_siblings: formatInput(siblings),
    }
}

export const generateCircuitInput = (nameDobSmt: SMT, nameYobSmt: SMT, ofac?: boolean) => {
    let smileData = ofac ? OFAC_DUMMY_INPUT : NON_OFAC_DUMMY_INPUT;
    const msg = serializeSmileData(smileData).split('').map((x) => x.charCodeAt(0));
    const sk = BigInt(subOrder - BigInt(Math.floor(Math.random() * 90098)));
    const pk = mulPointEscalar(Base8, sk);

    const nameDobInputs = generateCircuitInputsOfac(smileData, nameDobSmt, 2);
    const nameYobInputs = generateCircuitInputsOfac(smileData, nameYobSmt, 1);

    const sig = signECDSA(sk, msg)
    console.assert(verifyECDSA(msg, sig, pk) == true, "Invalid signature");

    let { T, U } = getEffECDSAArgs(msg, sig);
    console.assert(verifyEffECDSA(sig.s, T, U, pk) == true, "Invalid signature");

    console.assert(sig.s < subOrder, " s is greater than scalar field");
    console.assert(inCurve(T), "Point T not on curve");
    console.assert(inCurve(U), "Point U not on curve");

    const rInv = modInv(sig.R[0], subOrder);
    const rInvLimbs = bigintTo64bitLimbs(modulus(-rInv, subOrder));

    const idNumber = msg.slice(30, 30 + 20);
    const nullifierSig = signECDSA(sk, idNumber);
    console.assert(verifyECDSA(idNumber, nullifierSig, pk) == true, "Invalid signature");

    let { T: nullifierT, U: nullifierU } = getEffECDSAArgs(idNumber, nullifierSig);
    console.assert(verifyEffECDSA(nullifierSig.s, nullifierT, nullifierU, pk) == true, "Invalid signature");

    console.assert(nullifierSig.s < subOrder, " s is greater than scalar field");
    console.assert(inCurve(nullifierT), "Point T not on curve");
    console.assert(inCurve(nullifierU), "Point U not on curve");

    const rInvNullfier = modInv(nullifierSig.R[0], subOrder);
    const rInvNullfierLimbs = bigintTo64bitLimbs(modulus(-rInvNullfier, subOrder));

    const circuitInput: SelfricaCircuitInput = {
        SmileID_data: msg.map(String),
        // disclose_sel: Array.from({ length: SELFRICA_MAX_LENGTH }, () => (Math.floor(Math.random() * (2))).toString()),
        disclose_sel: Array(SELFRICA_MAX_LENGTH).fill('1'),
        s: sig.s.toString(),
        Tx: T[0].toString(),
        Ty: T[1].toString(),
        pubKeyX: pk[0].toString(),
        pubKeyY: pk[1].toString(),
        nullifier_s: nullifierSig.s.toString(),
        nullifier_Tx: nullifierT[0].toString(),
        nullifier_Ty: nullifierT[1].toString(),
        nullifier_Ux: nullifierU[0].toString(),
        nullifier_Uy: nullifierU[1].toString(),
        scope: '0',
        r_inv: rInvLimbs.map(String),
        r_inv_nullifier: rInvNullfierLimbs.map(String),
        forbidden_countries_list: ['0', '0', '0', '0', '0', '0','0', '0', '0'],
        ofac_name_dob_smt_leaf_key: nameDobInputs.smt_leaf_key,
        ofac_name_dob_smt_root: nameDobInputs.smt_root,
        ofac_name_dob_smt_siblings: nameDobInputs.smt_siblings,
        ofac_name_yob_smt_leaf_key: nameYobInputs.smt_leaf_key,
        ofac_name_yob_smt_root: nameYobInputs.smt_root,
        ofac_name_yob_smt_siblings: nameYobInputs.smt_siblings,
        selector_ofac: ['0'],
        attestation_id: ['4'],
        current_date: ['2', '0', '2', '5', '0', '1', '0', '1'],
        majority_age_ASCII: ['0', '2', '0'],
        selector_older_than: ['1'],
    }

    return circuitInput;
}

export const generateCircuitInputWithRealData = (serializedRealData: string, nameDobSmt: SMT, nameYobSmt: SMT, ofac?: boolean) => {
    const msg = serializedRealData.split('').map((x) => x.charCodeAt(0));
    const sk = BigInt(0x9053a34c294dc0eb08753613048fbbae1151939f05730995c72b18260b7b2e01n);
    const pk = mulPointEscalar(Base8, sk);

    const fullName = serializedRealData.slice(SELFRICA_FULL_NAME_INDEX, SELFRICA_FULL_NAME_INDEX + SELFRICA_FULL_NAME_LENGTH);
    const dob = serializedRealData.slice(SELFRICA_DOB_INDEX, SELFRICA_DOB_INDEX + SELFRICA_DOB_LENGTH);
    console.log(fullName);
    console.log(dob);

    const smileData = {
        fullName,
        dob,
    } as unknown as SmileData;

    const nameDobInputs = generateCircuitInputsOfac(smileData, nameDobSmt, 2);
    const nameYobInputs = generateCircuitInputsOfac(smileData, nameYobSmt, 1);

    const sig = signECDSA(sk, msg)
    console.assert(verifyECDSA(msg, sig, pk) == true, "Invalid signature");

    let { T, U } = getEffECDSAArgs(msg, sig);
    console.assert(verifyEffECDSA(sig.s, T, U, pk) == true, "Invalid signature");

    console.assert(sig.s < subOrder, " s is greater than scalar field");
    console.assert(inCurve(T), "Point T not on curve");
    console.assert(inCurve(U), "Point U not on curve");

    const rInv = modInv(sig.R[0], subOrder);
    const rInvLimbs = bigintTo64bitLimbs(modulus(-rInv, subOrder));

    const idNumber = msg.slice(30, 30 + 20);
    const nullifierSig = signECDSA(sk, idNumber);
    console.assert(verifyECDSA(idNumber, nullifierSig, pk) == true, "Invalid signature");

    let { T: nullifierT, U: nullifierU } = getEffECDSAArgs(idNumber, nullifierSig);
    console.assert(verifyEffECDSA(nullifierSig.s, nullifierT, nullifierU, pk) == true, "Invalid signature");

    console.assert(nullifierSig.s < subOrder, " s is greater than scalar field");
    console.assert(inCurve(nullifierT), "Point T not on curve");
    console.assert(inCurve(nullifierU), "Point U not on curve");

    const rInvNullfier = modInv(nullifierSig.R[0], subOrder);
    const rInvNullfierLimbs = bigintTo64bitLimbs(modulus(-rInvNullfier, subOrder));

    console.log("nullifierSig");
    console.log(nullifierSig.s);
    console.log(BigInt(nullifierSig.R[0]).toString(16));
    console.log(BigInt(nullifierSig.R[1]).toString(16));
    console.log("disclose sig");
    console.log(sig.s);
    console.log(BigInt(sig.R[0]).toString(16));
    console.log(BigInt(sig.R[1]).toString(16));
    console.log("nullifierT");
    console.log(BigInt(nullifierT[0]).toString(16));
    console.log(BigInt(nullifierT[1]).toString(16));
    console.log("T");
    console.log(BigInt(T[0]).toString(16));
    console.log(BigInt(T[1]).toString(16));

    const circuitInput: SelfricaCircuitInput = {
        SmileID_data: msg.map(String),
        // disclose_sel: Array.from({ length: SELFRICA_MAX_LENGTH }, () => (Math.floor(Math.random() * (2))).toString()),
        disclose_sel: Array(SELFRICA_MAX_LENGTH).fill('1'),
        s: sig.s.toString(),
        Tx: T[0].toString(),
        Ty: T[1].toString(),
        pubKeyX: pk[0].toString(),
        pubKeyY: pk[1].toString(),
        nullifier_s: nullifierSig.s.toString(),
        nullifier_Tx: nullifierT[0].toString(),
        nullifier_Ty: nullifierT[1].toString(),
        nullifier_Ux: nullifierU[0].toString(),
        nullifier_Uy: nullifierU[1].toString(),
        scope: '0',
        r_inv: rInvLimbs.map(String),
        r_inv_nullifier: rInvNullfierLimbs.map(String),
        forbidden_countries_list: ['0', '0', '0', '0', '0', '0','0', '0', '0'],
        ofac_name_dob_smt_leaf_key: nameDobInputs.smt_leaf_key,
        ofac_name_dob_smt_root: nameDobInputs.smt_root,
        ofac_name_dob_smt_siblings: nameDobInputs.smt_siblings,
        ofac_name_yob_smt_leaf_key: nameYobInputs.smt_leaf_key,
        ofac_name_yob_smt_root: nameYobInputs.smt_root,
        ofac_name_yob_smt_siblings: nameYobInputs.smt_siblings,
        selector_ofac: ['0'],
        attestation_id: ['4'],
    }

    return circuitInput;
}
