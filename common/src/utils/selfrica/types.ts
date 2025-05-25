import * as constants from './constants';
import { Point } from "@zk-kit/baby-jubjub";

export type SmileData = {
    country: string;
    idType: string;
    idNumber: string;
    issuanceDate: string;
    expiryDate: string;
    fullName: string;
    dob: string;
    photoHash: string;
    phoneNumber: string;
    document: string;
    gender: string;
    address: string;
};

export const serializeSmileData = (smileData: SmileData) => {
    //ensure max length of each field
    let serializedData = '';
    smileData.country = smileData.country.toUpperCase().padEnd(constants.SELFRICA_COUNTRY_LENGTH, '\0');
    smileData.idType = smileData.idType.toUpperCase().padEnd(constants.SELFRICA_ID_TYPE_LENGTH, '\0');
    smileData.idNumber = smileData.idNumber.padEnd(constants.SELFRICA_ID_NUMBER_LENGTH, '\0');
    smileData.issuanceDate = smileData.issuanceDate.padEnd(constants.SELFRICA_ISSUANCE_DATE_LENGTH, '\0');
    smileData.expiryDate = smileData.expiryDate.padEnd(constants.SELFRICA_EXPIRY_DATE_LENGTH, '\0');
    smileData.fullName = smileData.fullName.padEnd(constants.SELFRICA_FULL_NAME_LENGTH, '\0');
    smileData.dob = smileData.dob.padEnd(constants.SELFRICA_DOB_LENGTH, '\0');
    smileData.photoHash = smileData.photoHash.padEnd(constants.SELFRICA_PHOTO_HASH_LENGTH, '\0');
    smileData.phoneNumber = smileData.phoneNumber.padEnd(constants.SELFRICA_PHONE_NUMBER_LENGTH, '\0');
    smileData.document = smileData.document.padEnd(constants.SELFRICA_DOCUMENT_LENGTH, '\0');
    smileData.gender = smileData.gender.padEnd(constants.SELFRICA_GENDER_LENGTH, '\0');
    smileData.address = smileData.address.padEnd(constants.SELFRICA_ADDRESS_LENGTH, '\0');

    if (smileData.country.length !== constants.SELFRICA_COUNTRY_LENGTH) {
        throw new Error(`Country must be ${constants.SELFRICA_COUNTRY_LENGTH} characters`);
    }
    serializedData += smileData.country;

    if (smileData.idType.length !== constants.SELFRICA_ID_TYPE_LENGTH) {
        throw new Error(`ID type must be ${constants.SELFRICA_ID_TYPE_LENGTH} characters`);
    }
    serializedData += smileData.idType;

    if (smileData.idNumber.length !== constants.SELFRICA_ID_NUMBER_LENGTH) {
        throw new Error(`ID number must be ${constants.SELFRICA_ID_NUMBER_LENGTH} characters`);
    }
    serializedData += smileData.idNumber;

    if (smileData.issuanceDate.length !== constants.SELFRICA_ISSUANCE_DATE_LENGTH) {
        throw new Error(`Issuance date must be ${constants.SELFRICA_ISSUANCE_DATE_LENGTH} characters`);
    }
    serializedData += smileData.issuanceDate;

    if (smileData.expiryDate.length !== constants.SELFRICA_EXPIRY_DATE_LENGTH) {
        throw new Error(`Expiry date must be ${constants.SELFRICA_EXPIRY_DATE_LENGTH} characters`);
    }
    serializedData += smileData.expiryDate;

    if (smileData.fullName.length !== constants.SELFRICA_FULL_NAME_LENGTH) {
        throw new Error(`Full name must be ${constants.SELFRICA_FULL_NAME_LENGTH} characters`);
    }
    serializedData += smileData.fullName;

    if (smileData.dob.length !== constants.SELFRICA_DOB_LENGTH) {
        throw new Error(`DOB must be ${constants.SELFRICA_DOB_LENGTH} characters`);
    }
    serializedData += smileData.dob;

    if (smileData.photoHash.length !== constants.SELFRICA_PHOTO_HASH_LENGTH) {
        throw new Error(`Photo hash must be ${constants.SELFRICA_PHOTO_HASH_LENGTH} characters`);
    }
    serializedData += smileData.photoHash;

    if (smileData.phoneNumber.length !== constants.SELFRICA_PHONE_NUMBER_LENGTH) {
        throw new Error(`Phone number must be ${constants.SELFRICA_PHONE_NUMBER_LENGTH} characters`);
    }
    serializedData += smileData.phoneNumber;

    if (smileData.document.length !== constants.SELFRICA_DOCUMENT_LENGTH) {
        throw new Error(`Document must be ${constants.SELFRICA_DOCUMENT_LENGTH} characters`);
    }
    serializedData += smileData.document;

    if (smileData.gender.length !== constants.SELFRICA_GENDER_LENGTH) {
        throw new Error(`Gender must be ${constants.SELFRICA_GENDER_LENGTH} characters`);
    }
    serializedData += smileData.gender;

    if (smileData.address.length !== constants.SELFRICA_ADDRESS_LENGTH) {
        throw new Error(`Address must be ${constants.SELFRICA_ADDRESS_LENGTH} characters`);
    }
    serializedData += smileData.address;

    return serializedData;
}

export type Signature = {
    R: Point<bigint>,
    s: bigint
};

export type SelfricaCircuitInput = {
    SmileID_data: string[],
    disclose_sel: string[],
    s: string,
    Tx: string,
    Ty: string,
    pubKeyX: string,
    pubKeyY: string,
    r_inv: string[]
};