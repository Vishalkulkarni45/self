pragma circom 2.1.9;

include "circomlib/circuits/comparators.circom";
include "@openpassport/zk-email-circuits/utils/bytes.circom";

/// @notice CountryNotInList template — used to prove that the user is not from a list of forbidden countries
/// @param MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH Maximum number of countries present in the forbidden countries list
/// @param COUNTRY_LENGTH Length of the country (can be an alpha-2 code or alpha-3 code)
/// @input country Country of the user
/// @input forbidden_countries_list Forbidden countries list user wants to prove he is not from
/// @output forbidden_countries_list_packed Packed forbidden countries list — gas optimized

template CountryNotInList(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH, COUNTRY_LENGTH) {
    signal input country[COUNTRY_LENGTH];
    signal input forbidden_countries_list[MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH * COUNTRY_LENGTH];

    signal equality_result[MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH][COUNTRY_LENGTH + 1]; 
    signal is_equal[MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH][COUNTRY_LENGTH];
    for (var i = 0; i < MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH; i++) {
        equality_result[i][0] <== 1;
        for (var j = 1; j < COUNTRY_LENGTH + 1; j++) {
            is_equal[i][j - 1] <== IsEqual()([country[j - 1], forbidden_countries_list[i * COUNTRY_LENGTH + j - 1]]);
            equality_result[i][j] <== is_equal[i][j - 1] * equality_result[i][j - 1];
        }
        0 === equality_result[i][COUNTRY_LENGTH];
    }

    var chunkLength = computeIntChunkLength(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH * COUNTRY_LENGTH);
    signal output forbidden_countries_list_packed[chunkLength]  <== PackBytes(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH * COUNTRY_LENGTH)(forbidden_countries_list);
}
