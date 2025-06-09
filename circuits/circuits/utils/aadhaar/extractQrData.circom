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
    // Get year, month, name as int (DD-MM-YYYY format)
    signal output year <== DigitBytesToInt(4)([shiftedBytes[7], shiftedBytes[8], shiftedBytes[9], shiftedBytes[10]]);
    signal output month <== DigitBytesToInt(2)([shiftedBytes[4], shiftedBytes[5]]);
    signal output day <== DigitBytesToInt(2)([shiftedBytes[1], shiftedBytes[2]]);

    nDelimitedDataShiftedToDob <== shiftedBytes;
}

/// @title NameExtractor
/// @notice Extracts Name
/// @notice This assumes max name length  62 bytes
/// @param maxDataLength - Maximum length of the data
/// @param extractPosition - Position of the data to extract (after which delimiter does the data start)
/// @input nDelimitedData[maxDataLength] - QR data where each delimiter is 255 * n where n is order of the data
/// @input delimiterIndices - indices of the delimiters in the QR data
/// @output out - 2 field (int) element representing the data in big endian order (reverse string when decoded)
template NameExtractor(maxDataLength) {
    signal input nDelimitedData[maxDataLength];
    signal input delimiterIndices[18];

    signal output out[2];

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
    component outInt = PackBytes(nameMaxLength);
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

/// @title PinCodeExtractor
/// @notice Extracts the pin code from the Aadhaar QR data
/// @input nDelimitedData[maxDataLength] - QR data where each delimiter is 255 * n where n is order of the data
/// @input startDelimiterIndex - index of the delimiter after which the pin code start
/// @input endDelimiterIndex - index of the delimiter up to which the pin code is present
/// @output out - pinCode as integer
template PinCodeExtractor(maxDataLength) {
    signal input nDelimitedData[maxDataLength];
    signal input startDelimiterIndex;
    signal input endDelimiterIndex;

    signal output out;

    var pinCodeMaxLength = 6;
    var byteLength = pinCodeMaxLength + 2; // 2 delimiters

    component subArraySelector = SelectSubArray(maxDataLength, byteLength);
    subArraySelector.in <== nDelimitedData;
    subArraySelector.startIndex <== startDelimiterIndex;
    subArraySelector.length <== endDelimiterIndex - startDelimiterIndex + 1;

    signal shiftedBytes[byteLength] <== subArraySelector.out;

    // Assert delimiters around the data is correct
    shiftedBytes[0] === pinCodePosition() * 255;
    shiftedBytes[7] === (pinCodePosition() + 1) * 255;

    out <== DigitBytesToInt(6)([shiftedBytes[1], shiftedBytes[2], shiftedBytes[3], shiftedBytes[4], shiftedBytes[5], shiftedBytes[6]]);
}

function phnoPosition() {
    return 17;
}

template PhnoLast4DigitCodeExtractor(maxDataLength) {
    signal input nDelimitedData[maxDataLength];
    signal input startDelimiterIndex;
    signal input endDelimiterIndex;

    signal output out;

    var pinCodeMaxLength = 4;
    var byteLength = pinCodeMaxLength + 2; // 2 delimiters

    component subArraySelector = SelectSubArray(maxDataLength, byteLength);
    subArraySelector.in <== nDelimitedData;
    subArraySelector.startIndex <== startDelimiterIndex;
    subArraySelector.length <== endDelimiterIndex - startDelimiterIndex + 1;

    signal shiftedBytes[byteLength] <== subArraySelector.out;

    // Assert delimiters around the data is correct
    shiftedBytes[0] === phnoPosition() * 255;
    shiftedBytes[5] === (phnoPosition() + 1) * 255;

    out <== DigitBytesToInt(4)([shiftedBytes[1], shiftedBytes[2], shiftedBytes[3], shiftedBytes[4]]);
}

/// @title ExtractAndPackAsInt
/// @notice Helper function to extract data at a position to a single int (assumes data is less than 31 bytes)
/// @dev This is only used for state now;
/// @param maxDataLength - Maximum length of the data
/// @param extractPosition - Position of the data to extract (after which delimiter does the data start)
/// @input nDelimitedData[maxDataLength] - QR data where each delimiter is 255 * n where n is order of the data
/// @input delimiterIndices - indices of the delimiters in the QR data
/// @output out - single field (int) element representing the data in big endian order (reverse string when decoded)
template ExtractAndPackAsInt(maxDataLength, extractPosition) {
    signal input nDelimitedData[maxDataLength];
    signal input delimiterIndices[18];

    signal output out;

    signal startDelimiterIndex <== delimiterIndices[extractPosition - 1];
    signal endDelimiterIndex <== delimiterIndices[extractPosition];

    var extractMaxLength = maxFieldByteSize(); // Packing data only as a single int
    var byteLength = extractMaxLength + 1;

    // Shift the data to the right till the the delimiter start
    component subArraySelector = SelectSubArray(maxDataLength, byteLength);
    subArraySelector.in <== nDelimitedData;
    subArraySelector.startIndex <== startDelimiterIndex; // We want delimiter to be the first byte
    subArraySelector.length <== endDelimiterIndex - startDelimiterIndex;
    signal shiftedBytes[byteLength] <== subArraySelector.out;

    // Assert that the first byte is the delimiter (255 * position of the field)
    shiftedBytes[0] === extractPosition * 255;

    // Assert that last byte is the delimiter (255 * (position of the field + 1))
    component endDelimiterSelector = ItemAtIndex(maxDataLength);
    endDelimiterSelector.in <== nDelimitedData;
    endDelimiterSelector.index <== endDelimiterIndex;
    endDelimiterSelector.out === (extractPosition + 1) * 255;

    // Pack byte[] to int[] where int is field element which take up to 31 bytes
    component outInt = PackBytes(extractMaxLength);
    for (var i = 0; i < extractMaxLength; i ++) {
        outInt.in[i] <== shiftedBytes[i + 1]; // +1 to skip the delimiter
    }

    out <== outInt.out[0];
}


/// @title PhotoExtractor
/// @notice Extracts the photo from the Aadhaar QR data
/// @dev Not reusing ExtractAndPackAsInt as there is no endDelimiter (photo is last item)
/// @input nDelimitedData[maxDataLength] - QR data where each delimiter is 255 * n where n is order of the data
/// @input startDelimiterIndex - index of the delimiter after which the photo start
/// @input endIndex - index of the last byte of the photo
/// @output out - int[33] representing the photo in big endian order
template PhotoExtractor(maxDataLength) {
    signal input nDelimitedData[maxDataLength];
    signal input startDelimiterIndex;
    signal input endIndex;

    signal output out;

    var photoMaxLength = photoPackSize() * maxFieldByteSize();
    var bytesLength = photoMaxLength + 1;

    // Shift the data to the right to until the photo index
    component subArraySelector = SelectSubArray(maxDataLength, bytesLength);
    subArraySelector.in <== nDelimitedData;
    subArraySelector.startIndex <== startDelimiterIndex; // We want delimiter to be the first byte
    subArraySelector.length <== endIndex - startDelimiterIndex + 1;

    signal shiftedBytes[bytesLength] <== subArraySelector.out;

    // Assert that the first byte is the delimiter (255 * position of name field)
    shiftedBytes[0] === photoPosition() * 255;

    // Pack byte[] to int[] where int is field element which take up to 31 bytes
    // When packing like this the trailing 0s in each chunk would be removed as they are LSB
    // This is ok for being used in nullifiers as the behaviour would be consistent
    component outInt = PackBytesAndPoseidon(photoMaxLength);
    for (var i = 0; i < photoMaxLength; i ++) {
        outInt.in[i] <== shiftedBytes[i + 1]; // +1 to skip the delimiter
    }

    out <== outInt.out;
}


template EXTRACT_QR_DATA(maxDataLength) {
    signal input data[maxDataLength];
    signal input qrDataPaddedLength;
    signal input delimiterIndices[18];

    signal output name[2];
    signal output yob;
    signal output mob;
    signal output dob;
    signal output gender;
    signal output pincode;
    signal output state;
    signal output aadhaar_last_4digits;
    signal output ph_no_last_4digits;

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
    component nameExtractor = NameExtractor(maxDataLength);
    nameExtractor.nDelimitedData <== nDelimitedData;
    nameExtractor.delimiterIndices <== delimiterIndices;
    name <== nameExtractor.out;


    //Extract last 4 digit of Aadhar no
    aadhaar_last_4digits <== DigitBytesToInt(4)([nDelimitedData[5],nDelimitedData[6],nDelimitedData[7],nDelimitedData[8]]);

    // Extract date of birth
    component dobExtractor = DOBExtractor(maxDataLength);
    dobExtractor.nDelimitedData <== nDelimitedData;
    dobExtractor.startDelimiterIndex <== delimiterIndices[dobPosition() - 1];

    yob <== dobExtractor.year;
    mob <== dobExtractor.month;
    dob <== dobExtractor.day;

    // Extract gender
    // dobExtractor returns data shifted till DOB. Since size for DOB data is fixed,
    // we can use the same shifted data to extract gender.
    component genderExtractor = GenderExtractor(maxDataLength);
    genderExtractor.nDelimitedDataShiftedToDob <== dobExtractor.nDelimitedDataShiftedToDob;
    gender <== genderExtractor.out;

    component pinCodeExtractor = PinCodeExtractor(maxDataLength);
    pinCodeExtractor.nDelimitedData <== nDelimitedData;
    pinCodeExtractor.startDelimiterIndex <== delimiterIndices[pinCodePosition() - 1];
    pinCodeExtractor.endDelimiterIndex <== delimiterIndices[pinCodePosition()];
    pincode <== pinCodeExtractor.out;

    // Extract last 4 digits of phone number
    component phnoLast4DigitCodeExtractor = PhnoLast4DigitCodeExtractor(maxDataLength);
    phnoLast4DigitCodeExtractor.nDelimitedData <== nDelimitedData;
    phnoLast4DigitCodeExtractor.startDelimiterIndex <== delimiterIndices[phnoPosition() - 1];
    phnoLast4DigitCodeExtractor.endDelimiterIndex <== delimiterIndices[phnoPosition()];
    ph_no_last_4digits <== phnoLast4DigitCodeExtractor.out;
    // Extract state
    component stateExtractor = ExtractAndPackAsInt(maxDataLength, statePosition());
    stateExtractor.nDelimitedData <== nDelimitedData;
    stateExtractor.delimiterIndices <== delimiterIndices;
    state <== stateExtractor.out;

    // Extract photo
    component photoExtractor = PhotoExtractor(maxDataLength);
    photoExtractor.nDelimitedData <== nDelimitedData;
    photoExtractor.startDelimiterIndex <== delimiterIndices[photoPosition() - 1];
    photoExtractor.endIndex <== qrDataPaddedLength - 1;
    signal output photoHash <== photoExtractor.out;


}
