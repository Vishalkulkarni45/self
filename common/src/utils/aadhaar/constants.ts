
export const MAX_FIELD_BYTE_SIZE = 31;
export const NAME_MAX_LENGTH = 2 * MAX_FIELD_BYTE_SIZE; // 62 bytes
export const TOTAL_REVEAL_DATA_LENGTH = 119;

// Field lengths
export const FIELD_LENGTHS = {
  GENDER: 1,
  YEAR_OF_BIRTH: 4,
  MONTH_OF_BIRTH: 2,
  DAY_OF_BIRTH: 2,
  NAME: NAME_MAX_LENGTH, // 62
  AADHAAR_LAST_4_DIGITS: 4,
  PINCODE: 6,
  STATE: MAX_FIELD_BYTE_SIZE, // 31
  PHONE_LAST_4_DIGITS: 4,
  OFAC_NAME_DOB_CHECK: 1,
  OFAC_NAME_YOB_CHECK: 1,
  MINIMUM_AGE: 1,
} as const;

export const REVEAL_DATA_INDICES = {
  GENDER: 0,
  YEAR_OF_BIRTH_START: 1,
  MONTH_OF_BIRTH_START: 5,
  DAY_OF_BIRTH_START: 7,
  NAME_START: 9,
  AADHAAR_LAST_4_DIGITS_START: 71,
  PINCODE_START: 75,
  STATE_START: 81,
  PHONE_LAST_4_DIGITS_START: 112,
  OFAC_NAME_DOB_CHECK: 116,
  OFAC_NAME_YOB_CHECK: 117,
  MINIMUM_AGE: 118,
} as const;

// End indices (exclusive) for each field in revealedDataPacked array
export const REVEAL_DATA_END_INDICES = {
  GENDER: REVEAL_DATA_INDICES.GENDER + FIELD_LENGTHS.GENDER,
  YEAR_OF_BIRTH_END: REVEAL_DATA_INDICES.YEAR_OF_BIRTH_START + FIELD_LENGTHS.YEAR_OF_BIRTH,
  MONTH_OF_BIRTH_END: REVEAL_DATA_INDICES.MONTH_OF_BIRTH_START + FIELD_LENGTHS.MONTH_OF_BIRTH,
  DAY_OF_BIRTH_END: REVEAL_DATA_INDICES.DAY_OF_BIRTH_START + FIELD_LENGTHS.DAY_OF_BIRTH,
  NAME_END: REVEAL_DATA_INDICES.NAME_START + FIELD_LENGTHS.NAME,
  AADHAAR_LAST_4_DIGITS_END: REVEAL_DATA_INDICES.AADHAAR_LAST_4_DIGITS_START + FIELD_LENGTHS.AADHAAR_LAST_4_DIGITS,
  PINCODE_END: REVEAL_DATA_INDICES.PINCODE_START + FIELD_LENGTHS.PINCODE,
  STATE_END: REVEAL_DATA_INDICES.STATE_START + FIELD_LENGTHS.STATE,
  PHONE_LAST_4_DIGITS_END: REVEAL_DATA_INDICES.PHONE_LAST_4_DIGITS_START + FIELD_LENGTHS.PHONE_LAST_4_DIGITS,
  OFAC_NAME_DOB_CHECK_END: REVEAL_DATA_INDICES.OFAC_NAME_DOB_CHECK + FIELD_LENGTHS.OFAC_NAME_DOB_CHECK,
  OFAC_NAME_YOB_CHECK_END: REVEAL_DATA_INDICES.OFAC_NAME_YOB_CHECK + FIELD_LENGTHS.OFAC_NAME_YOB_CHECK,
  MINIMUM_AGE_END: REVEAL_DATA_INDICES.MINIMUM_AGE + FIELD_LENGTHS.MINIMUM_AGE,
} as const;

// Range definitions for easy array slicing
export const REVEAL_DATA_RANGES = {
  GENDER: [REVEAL_DATA_INDICES.GENDER, REVEAL_DATA_END_INDICES.GENDER] as const,
  YEAR_OF_BIRTH: [REVEAL_DATA_INDICES.YEAR_OF_BIRTH_START, REVEAL_DATA_END_INDICES.YEAR_OF_BIRTH_END] as const,
  MONTH_OF_BIRTH: [REVEAL_DATA_INDICES.MONTH_OF_BIRTH_START, REVEAL_DATA_END_INDICES.MONTH_OF_BIRTH_END] as const,
  DAY_OF_BIRTH: [REVEAL_DATA_INDICES.DAY_OF_BIRTH_START, REVEAL_DATA_END_INDICES.DAY_OF_BIRTH_END] as const,
  NAME: [REVEAL_DATA_INDICES.NAME_START, REVEAL_DATA_END_INDICES.NAME_END] as const,
  AADHAAR_LAST_4_DIGITS: [REVEAL_DATA_INDICES.AADHAAR_LAST_4_DIGITS_START, REVEAL_DATA_END_INDICES.AADHAAR_LAST_4_DIGITS_END] as const,
  PINCODE: [REVEAL_DATA_INDICES.PINCODE_START, REVEAL_DATA_END_INDICES.PINCODE_END] as const,
  STATE: [REVEAL_DATA_INDICES.STATE_START, REVEAL_DATA_END_INDICES.STATE_END] as const,
  PHONE_LAST_4_DIGITS: [REVEAL_DATA_INDICES.PHONE_LAST_4_DIGITS_START, REVEAL_DATA_END_INDICES.PHONE_LAST_4_DIGITS_END] as const,
  OFAC_NAME_DOB_CHECK: [REVEAL_DATA_INDICES.OFAC_NAME_DOB_CHECK, REVEAL_DATA_END_INDICES.OFAC_NAME_DOB_CHECK_END] as const,
  OFAC_NAME_YOB_CHECK: [REVEAL_DATA_INDICES.OFAC_NAME_YOB_CHECK, REVEAL_DATA_END_INDICES.OFAC_NAME_YOB_CHECK_END] as const,
  MINIMUM_AGE: [REVEAL_DATA_INDICES.MINIMUM_AGE, REVEAL_DATA_END_INDICES.MINIMUM_AGE_END] as const,
} as const;

// Selector bit positions corresponding to each field (for creating selector bitmap)
export const SELECTOR_BITS = {
  GENDER: 0,
  YEAR_OF_BIRTH: [1, 2, 3, 4] as const,
  MONTH_OF_BIRTH: [5, 6] as const,
  DAY_OF_BIRTH: [7, 8] as const,
  NAME: Array.from({ length: NAME_MAX_LENGTH }, (_, i) => i + 9) as number[], // indices 9-70
  AADHAAR_LAST_4_DIGITS: [71, 72, 73, 74] as const,
  PINCODE: [75, 76, 77, 78, 79, 80] as const,
  STATE: Array.from({ length: MAX_FIELD_BYTE_SIZE }, (_, i) => i + 81) as number[], // indices 81-111
  PHONE_LAST_4_DIGITS: [112, 113, 114, 115] as const,
  PHOTO_HASH: 116,
  OFAC_NAME_DOB_CHECK: 117,
  OFAC_NAME_YOB_CHECK: 118,
} as const;

export type AadhaarField = keyof typeof FIELD_LENGTHS;

/**
 * Helper function to extract a specific field from unpacked reveal data
 * @param unpackedData - The unpacked reveal data array (119 elements)
 * @param field - The field to extract
 * @returns The extracted field data as a string or number
 */
export function extractField(unpackedData: string[], field: AadhaarField): string | number {
  const range = REVEAL_DATA_RANGES[field];
  if (range[1] - range[0] === 1) {
    // Single value field
    const value = unpackedData[range[0]];
    // Handle special cases for numeric/boolean fields
    if (field === 'OFAC_NAME_DOB_CHECK' || field === 'OFAC_NAME_YOB_CHECK' || field === 'MINIMUM_AGE') {
      return value.charCodeAt(0);
    }
    return value;
  } else {

    return unpackedData.slice(range[0], range[1])
      .join('')
      .replace(/\0+$/, '');
  }
}

/**
 * Helper function to create a selector field for revealing specific data
 * @param fieldsToReveal - Array of field names to reveal
 * @returns Selector value as bigint
 */
export function createSelector(fieldsToReveal: AadhaarField[]): bigint {
  const bits = Array(119).fill(0);

  for (const field of fieldsToReveal) {
    const selectorBits = SELECTOR_BITS[field];
    if (Array.isArray(selectorBits)) {
      for (const bit of selectorBits) {
        bits[bit] = 1;
      }
    } else {
      bits[selectorBits] = 1;
    }
  }

  let result = 0n;
  for (let i = 0; i < 119; i++) {
    if (bits[i]) {
      result += 1n << BigInt(i);
    }
  }

  return result;
}

// Commonly used field combinations
export const COMMON_FIELD_COMBINATIONS = {
  BASIC_INFO: ['GENDER', 'YEAR_OF_BIRTH', 'MONTH_OF_BIRTH', 'DAY_OF_BIRTH'] as AadhaarField[],
  IDENTITY: ['NAME', 'YEAR_OF_BIRTH', 'MONTH_OF_BIRTH', 'DAY_OF_BIRTH'] as AadhaarField[],
  LOCATION: ['STATE', 'PINCODE'] as AadhaarField[],
  CONTACT: ['PHONE_LAST_4_DIGITS'] as AadhaarField[],
  OFAC_CHECKS: ['OFAC_NAME_DOB_CHECK', 'OFAC_NAME_YOB_CHECK'] as AadhaarField[],
  ALL_FIELDS: Object.keys(FIELD_LENGTHS) as AadhaarField[],
} as const;
