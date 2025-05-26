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

export const generateCircuitInput = () => {
    const msg = serializeSmileData(OFAC_DUMMY_INPUT).split('').map((x) => x.charCodeAt(0));
    const sk = BigInt(subOrder - BigInt(Math.floor(Math.random() * 90098)));
    const pk = mulPointEscalar(Base8, sk);

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
        disclose_sel: Array.from({ length: SELFRICA_MAX_LENGTH }, () => (Math.floor(Math.random() * (2))).toString()),
        s: sig.s.toString(),
        Tx: T[0].toString(),
        Ty: T[1].toString(),
        pubKeyX: pk[0].toString(),
        pubKeyY: pk[1].toString(),
        r_inv: rInvLimbs.map(String)
    }

    return circuitInput;
}