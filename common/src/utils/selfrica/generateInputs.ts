import { SMT } from "@openpassport/zk-kit-smt";
import { generateSMTProof, getNameDobLeafSelfrica, getNameYobLeafSelfrica } from "../trees.js";
import { SelfricaCircuitInput, serializeSmileData, SmileData } from "./types.js";
import { formatInput } from "../circuits/generateInputs.js";
import { sha256Pad } from '@zk-email/helpers/dist/sha-utils.js';
import { SELFRICA_DOB_INDEX, SELFRICA_DOB_LENGTH, SELFRICA_FULL_NAME_INDEX, SELFRICA_FULL_NAME_LENGTH, SELFRICA_MAX_LENGTH } from "./constants.js";
import { generateRSAKeyPair, signRSA, verifyRSA } from "./rsa.js";
import crypto from "crypto";
import { splitToWords } from "../bytes.js";


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
    const msg = Buffer.from(serializeSmileData(smileData), 'utf8');
    const msgArray = Array.from(msg);

    // Generate RSA key pair
    const { publicKey, privateKey } = generateRSAKeyPair();

    const nameDobInputs = generateCircuitInputsOfac(smileData, nameDobSmt, 2);
    const nameYobInputs = generateCircuitInputsOfac(smileData, nameYobSmt, 1);

    const [msgPadded, _]= sha256Pad(msg, 320);

    // Sign with RSA
    const msg_rsaSig = signRSA(msg, privateKey);
    console.assert(verifyRSA(msg, msg_rsaSig, publicKey) == true, "Invalid RSA signature");

    // Convert RSA signature to limbs for circuit input
    const sigBigInt = BigInt('0x' + msg_rsaSig.toString('hex'));

    // Sign nullifier with RSA
    const idNumber = Buffer.from(msgArray.slice(30, 30 + 20));

    const id_num_rsaSig = signRSA(idNumber, privateKey);
    console.assert(verifyRSA(idNumber, id_num_rsaSig, publicKey) == true, "Invalid nullifier RSA signature");

    // Convert nullifier RSA signature to limbs
    const nullifierSigBigInt = BigInt('0x' + id_num_rsaSig.toString('hex'));

    // Extract RSA modulus and exponent from PEM formatted public key
    const publicKeyObject = crypto.createPublicKey(publicKey);
    const jwk = publicKeyObject.export({ format: 'jwk' });
    const rsaModulus = BigInt('0x' + Buffer.from(jwk.n as string, 'base64url').toString('hex'));

    const circuitInput: SelfricaCircuitInput = {
        SmileID_data_padded: formatInput(msgPadded),
        // disclose_sel: Array.from({ length: SELFRICA_MAX_LENGTH }, () => (Math.floor(Math.random() * (2))).toString()),
        disclose_sel: Array(SELFRICA_MAX_LENGTH).fill('1'),
        pubKey: splitToWords(rsaModulus, 121, 17),
        msg_sig: splitToWords(sigBigInt, 121, 17),
        scope: '0',
        id_num_sig: splitToWords(nullifierSigBigInt, 121, 17),
        forbidden_countries_list: [...Array(120)].map((x) => '0'),
        ofac_name_dob_smt_leaf_key: nameDobInputs.smt_leaf_key,
        ofac_name_dob_smt_root: nameDobInputs.smt_root,
        ofac_name_dob_smt_siblings: nameDobInputs.smt_siblings,
        ofac_name_yob_smt_leaf_key: nameYobInputs.smt_leaf_key,
        ofac_name_yob_smt_root: nameYobInputs.smt_root,
        ofac_name_yob_smt_siblings: nameYobInputs.smt_siblings,
        selector_ofac: ['0'],
        attestation_id: ['4'],
        user_identifier: '1234567890',
        current_date: ['2', '0', '2', '4', '0', '1', '0', '1'],
        majority_age_ASCII: ['0', '0', '1'].map((x) => x.charCodeAt(0)),
        selector_older_than: ['1'],
    }

    return circuitInput;
}

export const generateCircuitInputWithRealData = (serializedRealData: string, nameDobSmt: SMT, nameYobSmt: SMT, ofac?: boolean) => {
    const msg = Buffer.from(serializedRealData, 'utf8');
    const msgArray = Array.from(msg); // Convert buffer to array of bytes for circuit input

    // Generate RSA key pair for real data (or use fixed key for deterministic results)
    const { publicKey, privateKey } = generateRSAKeyPair();

    const fullName = serializedRealData.slice(SELFRICA_FULL_NAME_INDEX, SELFRICA_FULL_NAME_INDEX + SELFRICA_FULL_NAME_LENGTH);
    const dob = serializedRealData.slice(SELFRICA_DOB_INDEX, SELFRICA_DOB_INDEX + SELFRICA_DOB_LENGTH);

    const smileData = {
        fullName,
        dob,
    } as unknown as SmileData;

    const nameDobInputs = generateCircuitInputsOfac(smileData, nameDobSmt, 2);
    const nameYobInputs = generateCircuitInputsOfac(smileData, nameYobSmt, 1);

    // Sign with RSA
    const rsaSig = signRSA(msg, privateKey);
    console.assert(verifyRSA(msg, rsaSig, publicKey) == true, "Invalid RSA signature");

    // Convert RSA signature to limbs for circuit input
    const sigBigInt = BigInt('0x' + rsaSig.toString('hex'));

    // Sign nullifier with RSA
    const idNumber = Buffer.from(msgArray.slice(30, 30 + 20));
    const nullifierRsaSig = signRSA(idNumber, privateKey);
    console.assert(verifyRSA(idNumber, nullifierRsaSig, publicKey) == true, "Invalid nullifier RSA signature");

    // Convert nullifier RSA signature to limbs
    const nullifierSigBigInt = BigInt('0x' + nullifierRsaSig.toString('hex'));

    // Extract RSA modulus and exponent from PEM formatted public key
    const publicKeyObject = crypto.createPublicKey(publicKey);
    const jwk = publicKeyObject.export({ format: 'jwk' });
    const realRsaModulus = BigInt('0x' + Buffer.from(jwk.n as string, 'base64url').toString('hex'));

    const [msgPadded, _] = sha256Pad(msg, 320);

    const circuitInput: SelfricaCircuitInput = {
        SmileID_data_padded: formatInput(msgPadded),
        // disclose_sel: Array.from({ length: SELFRICA_MAX_LENGTH }, () => (Math.floor(Math.random() * (2))).toString()),
        disclose_sel: Array(SELFRICA_MAX_LENGTH).fill('1'),
        // RSA signature components
        pubKey: splitToWords(realRsaModulus, 121, 17),
        msg_sig: splitToWords(sigBigInt, 121, 17),
        id_num_sig: splitToWords(nullifierSigBigInt, 121, 17),
        scope: '0',
        forbidden_countries_list: [...Array(120)].map((x) => '0'),
        ofac_name_dob_smt_leaf_key: nameDobInputs.smt_leaf_key,
        ofac_name_dob_smt_root: nameDobInputs.smt_root,
        ofac_name_dob_smt_siblings: nameDobInputs.smt_siblings,
        ofac_name_yob_smt_leaf_key: nameYobInputs.smt_leaf_key,
        ofac_name_yob_smt_root: nameYobInputs.smt_root,
        ofac_name_yob_smt_siblings: nameYobInputs.smt_siblings,
        selector_ofac: ['0'],
        attestation_id: ['4'],
        user_identifier: '1234567890',
        current_date: ['2', '0', '2', '4', '0', '1', '0', '1'],
        majority_age_ASCII: ['0', '2', '0'].map((x) => x.charCodeAt(0)),
        selector_older_than: ['1'],
    }

    return circuitInput;
}
