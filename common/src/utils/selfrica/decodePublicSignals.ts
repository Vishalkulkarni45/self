import { unpackReveal } from "../circuits/formatOutputs.js";
import {
    SELFRICA_MAX_LENGTH,
    SELFRICA_PUBLIC_SIGNALS_ATTESTATION_ID,
    SELFRICA_PUBLIC_SIGNALS_FORBIDDEN_COUNTRIES_PACKED,
    SELFRICA_PUBLIC_SIGNALS_OFAC_NAME_DOB_SMT_ROOT,
    SELFRICA_PUBLIC_SIGNALS_REVEALED_DATA_PACKED,
    SELFRICA_PUBLIC_SIGNALS_REVEALED_DATA_PACKED_LENGTH,
    SELFRICA_PUBLIC_SIGNALS_IDENTITY_COMMITMENT,
    SELFRICA_PUBLIC_SIGNALS_NULLIFIER,
    SELFRICA_PUBLIC_SIGNALS_PUBKEY_X,
    SELFRICA_PUBLIC_SIGNALS_PUBKEY_Y,
    SELFRICA_PUBLIC_SIGNALS_SCOPE,
    SELFRICA_PUBLIC_SIGNALS_OFAC_NAME_YOB_SMT_ROOT,
    SELFRICA_PUBLIC_SIGNALS_FORBIDDEN_COUNTRIES_PACKED_LENGTH,
    SELFRICA_PUBLIC_SIGNALS_CURRENT_DATE,
    SELFRICA_PUBLIC_SIGNALS_CURRENT_DATE_LENGTH,
    SELFRICA_PUBLIC_SIGNALS_USER_IDENTIFIER
} from "./constants.js";

export const decodePublicSignals = (publicSignals: string[]) => {
    const revealedDataPacked = publicSignals.slice(SELFRICA_PUBLIC_SIGNALS_REVEALED_DATA_PACKED, SELFRICA_PUBLIC_SIGNALS_REVEALED_DATA_PACKED + SELFRICA_PUBLIC_SIGNALS_REVEALED_DATA_PACKED_LENGTH);
    const revealedDataUnpacked = unpackReveal(revealedDataPacked, 'id').slice(0, SELFRICA_MAX_LENGTH + 2 + 3);

    const forbiddenCountriesPacked = publicSignals.slice(SELFRICA_PUBLIC_SIGNALS_FORBIDDEN_COUNTRIES_PACKED, SELFRICA_PUBLIC_SIGNALS_FORBIDDEN_COUNTRIES_PACKED + SELFRICA_PUBLIC_SIGNALS_FORBIDDEN_COUNTRIES_PACKED_LENGTH);
    const forbiddenCountriesUnpacked = unpackReveal(forbiddenCountriesPacked, 'id');

    const identityCommitment = publicSignals[SELFRICA_PUBLIC_SIGNALS_IDENTITY_COMMITMENT];
    const nullifier = publicSignals[SELFRICA_PUBLIC_SIGNALS_NULLIFIER];
    const pubkeyX = publicSignals[SELFRICA_PUBLIC_SIGNALS_PUBKEY_X];
    const pubkeyY = publicSignals[SELFRICA_PUBLIC_SIGNALS_PUBKEY_Y];
    const scope = publicSignals[SELFRICA_PUBLIC_SIGNALS_SCOPE];
    const ofacNameDobSmtRoot = publicSignals[SELFRICA_PUBLIC_SIGNALS_OFAC_NAME_DOB_SMT_ROOT];
    const ofacNameYobSmtRoot = publicSignals[SELFRICA_PUBLIC_SIGNALS_OFAC_NAME_YOB_SMT_ROOT];
    const attestationId = publicSignals[SELFRICA_PUBLIC_SIGNALS_ATTESTATION_ID];
    const currentDate = publicSignals.slice(SELFRICA_PUBLIC_SIGNALS_CURRENT_DATE, SELFRICA_PUBLIC_SIGNALS_CURRENT_DATE + SELFRICA_PUBLIC_SIGNALS_CURRENT_DATE_LENGTH);

    return {
        revealedDataUnpacked,
        forbiddenCountriesUnpacked,
        identityCommitment,
        nullifier,
        pubkeyX,
        pubkeyY,
        scope,
        ofacNameDobSmtRoot,
        ofacNameYobSmtRoot,
        attestationId,
        userIdentifier: publicSignals[SELFRICA_PUBLIC_SIGNALS_USER_IDENTIFIER],
        currentDate,
    }
}
