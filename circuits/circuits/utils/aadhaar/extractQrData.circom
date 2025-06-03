pragma circom 2.1.9;

include "anon-aadhaar-circuits/src/helpers/constants.circom";
include "anon-aadhaar-circuits/src/utils/pack.circom";
include "circomlib/circuits/comparators.circom";
include "circomlib/circuits/bitify.circom";
include "circomlib/circuits/poseidon.circom";
include "../passport/customHashers.circom";


/// @title DOBExtractor
/// @notice Extract date of birth from the Aadhaar QR data
/// @param maxDataLength - Maximum length of the data
/// @input nDelimitedData[maxDataLength] - QR data where each delimiter is 255 * n where n is order of the data
/// @input startDelimiterIndex - index of the delimiter after which the date of birth start
template DOBExtractor(maxDataLength) {
    signal input nDelimitedData[maxDataLength];
    signal input startDelimiterIndex;

    signal output nDelimitedDataShiftedToDob[maxDataLength];

    // Shift the data to the right to until the DOB index
    // We are not using SubArraySelector as the shifted data is an output
    component shifter = VarShiftLeft(maxDataLength, maxDataLength);
    shifter.in <== nDelimitedData;
    shifter.shift <== startDelimiterIndex; // We want delimiter to be the first byte

    signal shiftedBytes[maxDataLength] <== shifter.out;

    // Assert delimiters around the data is correct
    shiftedBytes[0] === dobPosition() * 255;
    shiftedBytes[11] === (dobPosition() + 1) * 255;

    // Convert DOB bytes to unix timestamp.
    // Get year, month, name as int (DD-MM-YYYY format and starts from shiftedBytes[0])
    signal output year <== DigitBytesToInt(4)([shiftedBytes[7], shiftedBytes[8], shiftedBytes[9], shiftedBytes[10]]);
    signal output month <== DigitBytesToInt(2)([shiftedBytes[4], shiftedBytes[5]]);
    signal output day <== DigitBytesToInt(2)([shiftedBytes[1], shiftedBytes[2]]);

    nDelimitedDataShiftedToDob <== shiftedBytes;
}

/// @title NameExtractor
/// @notice Extracts Name and  returns hash of name
/// @notice This assumes max name length  62 bytes
/// @param maxDataLength - Maximum length of the data
/// @param extractPosition - Position of the data to extract (after which delimiter does the data start)
/// @input nDelimitedData[maxDataLength] - QR data where each delimiter is 255 * n where n is order of the data
/// @input delimiterIndices - indices of the delimiters in the QR data
/// @output out - 2 field (int) element representing the data in big endian order (reverse string when decoded)
template NameHashExtractor(maxDataLength) {
    signal input nDelimitedData[maxDataLength];
    signal input delimiterIndices[18];

    signal output out;

    signal startDelimiterIndex <== delimiterIndices[namePosition() - 1];
    signal endDelimiterIndex <== delimiterIndices[namePosition()];

    var nameMaxLength = 2 * maxFieldByteSize();
    var byteLength = nameMaxLength + 1;

    // Shift the data to the right till the the delimiter start
    component subArraySelector = SelectSubArray(maxDataLength, byteLength);
    subArraySelector.in <== nDelimitedData;
    subArraySelector.startIndex <== startDelimiterIndex; // We want delimiter to be the first byte
    subArraySelector.length <== endDelimiterIndex - startDelimiterIndex;
    signal shiftedBytes[byteLength] <== subArraySelector.out;

    // Assert that the first byte is the delimiter (255 * namePosition())
    shiftedBytes[0] === namePosition() * 255;

    // Assert that last byte is the delimiter (255 * (namePosition() + 1))
    component endDelimiterSelector = ItemAtIndex(maxDataLength);
    endDelimiterSelector.in <== nDelimitedData;
    endDelimiterSelector.index <== endDelimiterIndex;
    endDelimiterSelector.out === (namePosition() + 1) * 255;

    // Pack byte[] to int[] where int is field element which take up to 31 bytes
    component outInt = PackBytesAndPoseidon(nameMaxLength);
    for (var i = 0; i < nameMaxLength; i ++) {
        outInt.in[i] <== shiftedBytes[i + 1]; // +1 to skip the delimiter
    }

    out <== outInt.out;
}


/// @title GenderExtractor
/// @notice Extracts the Gender from the Aadhaar QR data and returns as Unix timestamp
/// @input nDelimitedDataShiftedToDob[maxDataLength] - QR data where each delimiter is 255 * n
///     where n is order of the data shifted till DOB index
/// @input startDelimiterIndex - index of the delimiter after
/// @output out Single byte number representing gender
template GenderExtractor(maxDataLength) {
    signal input nDelimitedDataShiftedToDob[maxDataLength];

    signal output out;

    // Gender is always 1 byte and is immediate after DOB
    // We use nDelimitedDataShiftedToDob and start after 10 + 1 bytes of DOB data
    // This is more efficient than using ItemAtIndex thrice (for startIndex, gender, endIndex)
    // saves around 14k constraints
    nDelimitedDataShiftedToDob[11] === genderPosition() * 255;
    nDelimitedDataShiftedToDob[13] === (genderPosition() + 1) * 255;

    out <== nDelimitedDataShiftedToDob[12];
}


template EXTRACT_QR_DATA(maxDataLength) {
    signal input data[maxDataLength];
    signal input qrDataPaddedLength;
    signal input delimiterIndices[18];

    signal output nameHash;
    signal output dobHash;
    signal output gender;

    // Create `nDelimitedData` - same as `data` but each delimiter is replaced with n * 255
    // where n means the nth occurrence of 255
    // This is to verify `delimiterIndices` is correctly set for each extraction
    component is255[maxDataLength];
    component indexBeforePhoto[maxDataLength];
    signal is255AndIndexBeforePhoto[maxDataLength];
    signal nDelimitedData[maxDataLength];
    signal n255Filter[maxDataLength + 1];
    n255Filter[0] <== 0;

    for (var i = 0; i < maxDataLength; i++) {
        is255[i] = IsEqual();
        is255[i].in[0] <== 255;
        is255[i].in[1] <== data[i];

        indexBeforePhoto[i] = LessThan(12);
        indexBeforePhoto[i].in[0] <== i;
        indexBeforePhoto[i].in[1] <== delimiterIndices[photoPosition() - 1] + 1;

        is255AndIndexBeforePhoto[i] <== is255[i].out * indexBeforePhoto[i].out;

        // Each value is n * 255 where n the count of 255s before it
        n255Filter[i + 1] <== is255AndIndexBeforePhoto[i] * 255 + n255Filter[i];

        nDelimitedData[i] <== is255AndIndexBeforePhoto[i] * n255Filter[i] + data[i];
    }

    //Extract name and hash
    component nameHashExtractor = NameHashExtractor(maxDataLength);
    nameHashExtractor.nDelimitedData <== nDelimitedData;
    nameHashExtractor.delimiterIndices <== delimiterIndices;
    nameHash <== nameHashExtractor.out;


    //Extract last 4 digit of Aadhar no
    signal output aadhaar_last_4digits <== DigitBytesToInt(4)([nDelimitedData[5],nDelimitedData[6],nDelimitedData[7],nDelimitedData[8]]);

    // Extract date of birth
    component dobExtractor = DOBExtractor(maxDataLength);
    dobExtractor.nDelimitedData <== nDelimitedData;
    dobExtractor.startDelimiterIndex <== delimiterIndices[dobPosition() - 1];

    dobHash <== Poseidon(3)([
        dobExtractor.year,
        dobExtractor.month,
        dobExtractor.day
    ]);

    // Extract gender
    // dobExtractor returns data shifted till DOB. Since size for DOB data is fixed,
    // we can use the same shifted data to extract gender.
    component genderExtractor = GenderExtractor(maxDataLength);
    genderExtractor.nDelimitedDataShiftedToDob <== dobExtractor.nDelimitedDataShiftedToDob;
    gender <== genderExtractor.out;

}
