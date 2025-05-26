import { SMT } from "@openpassport/zk-kit-smt";
import { generateSMTProof, getNameDobLeaf, getNameDobLeafSelfrica, getNameYobLeafSelfrica } from "../trees";
import { SelfricaCircuitInput, serializeSmileData, SmileData } from "./types";
import { formatInput } from "../circuits/generateInputs";
import { bigintTo64bitLimbs, generateRandomsg, getECDSAMessageHash, getEffECDSAArgs, modInv, modulus } from "./ecdsa/utils";
import { signECDSA, verifyECDSA, verifyEffECDSA } from "./ecdsa/ecdsa";
import { Base8, inCurve, mulPointEscalar, subOrder } from "@zk-kit/baby-jubjub";
import { SELFRICA_MAX_LENGTH } from "./constants";

export const OFAC_DUMMY_INPUT: SmileData = {
    country: 'KE',
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
};

export const NON_OFAC_DUMMY_INPUT: SmileData = {
    country: 'KE',
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
};

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

    const circuitInput: SelfricaCircuitInput = {
        SmileID_data: msg.map(String),
        // disclose_sel: Array.from({ length: SELFRICA_MAX_LENGTH }, () => (Math.floor(Math.random() * (2))).toString()),
        disclose_sel: Array(SELFRICA_MAX_LENGTH).fill('1'),
        s: sig.s.toString(),
        Tx: T[0].toString(),
        Ty: T[1].toString(),
        pubKeyX: pk[0].toString(),
        pubKeyY: pk[1].toString(),
        r_inv: rInvLimbs.map(String), 
        forbidden_countries_list: ['0', '0', '0', '0', '0', '0',],
        ofac_name_dob_smt_leaf_key: nameDobInputs.smt_leaf_key,
        ofac_name_dob_smt_root: nameDobInputs.smt_root,
        ofac_name_dob_smt_siblings: nameDobInputs.smt_siblings,
        ofac_name_yob_smt_leaf_key: nameYobInputs.smt_leaf_key,
        ofac_name_yob_smt_root: nameYobInputs.smt_root,
        ofac_name_yob_smt_siblings: nameYobInputs.smt_siblings,
        selector_ofac: ['0'],
    }

    return circuitInput;
}