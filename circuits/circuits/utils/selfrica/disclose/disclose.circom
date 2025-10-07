pragma circom 2.1.9;

include "./ofac/ofac_name_dob_selfrica.circom";
include "./ofac/ofac_name_yob_selfrica.circom";
include "./country_not_in_list.circom";
include "../date/isValid.circom";
include "../date/isOlderThan.circom";
include "../constants.circom";

template DISCLOSE_SELFRICA(
    MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH,
    name_dob_tree_levels,
    name_yob_tree_levels
) {
    var selfrica_max_length = SELFRICA_MAX_LENGTH();
    var country_length = COUNTRY_LENGTH();
    var country_index = COUNTRY_INDEX();
    signal input smile_data[selfrica_max_length];
    signal input selector_smile_data[selfrica_max_length];

    signal input forbidden_countries_list[MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH * country_length];

    signal input ofac_name_dob_smt_leaf_key;
    signal input ofac_name_dob_smt_root;
    signal input ofac_name_dob_smt_siblings[name_dob_tree_levels];

    signal input ofac_name_yob_smt_leaf_key;
    signal input ofac_name_yob_smt_root;
    signal input ofac_name_yob_smt_siblings[name_yob_tree_levels];

    signal input selector_ofac;
    signal input current_date[8];
    signal input majority_age_ASCII[3];
    signal input selector_older_than;

    selector_ofac * (selector_ofac - 1) === 0;

    signal validity_ASCII[8];
    for (var i = 0; i < EXPIRATION_DATE_LENGTH(); i++) {
        validity_ASCII[i] <== smile_data[EXPIRATION_DATE_INDEX() + i];
    }
    IsValidFullYear()(current_date, validity_ASCII);

    signal birth_date_ASCII[8];
    for (var i = 0; i < DOB_LENGTH(); i++) {
        birth_date_ASCII[i] <== smile_data[DOB_INDEX() + i];
    }

    component is_older_than = IsOlderThan();
    is_older_than.majorityASCII <== majority_age_ASCII;
    is_older_than.currDate <== current_date;
    is_older_than.birthDateASCII <== birth_date_ASCII;
    signal is_older_than_result <== is_older_than.out;


    component ofac_name_dob_circuit = OFAC_NAME_DOB_SELFRICA(name_dob_tree_levels);
    ofac_name_dob_circuit.smile_data <== smile_data;
    ofac_name_dob_circuit.smt_leaf_key <== ofac_name_dob_smt_leaf_key;
    ofac_name_dob_circuit.smt_root <== ofac_name_dob_smt_root;
    ofac_name_dob_circuit.smt_siblings <== ofac_name_dob_smt_siblings;

    component ofac_name_yob_circuit = OFAC_NAME_YOB_SELFRICA(name_yob_tree_levels);
    ofac_name_yob_circuit.smile_data <== smile_data;
    ofac_name_yob_circuit.smt_leaf_key <== ofac_name_yob_smt_leaf_key;
    ofac_name_yob_circuit.smt_root <== ofac_name_yob_smt_root;
    ofac_name_yob_circuit.smt_siblings <== ofac_name_yob_smt_siblings;

    signal older_than_verified[3];
    older_than_verified[0] <== is_older_than_result * majority_age_ASCII[0];
    older_than_verified[1] <== is_older_than_result * majority_age_ASCII[1];
    older_than_verified[2] <== is_older_than_result * majority_age_ASCII[2];

    signal revealed_data[selfrica_max_length + 2 + 3];
    for (var i = 0; i < selfrica_max_length; i++) {
        revealed_data[i] <== smile_data[i] * selector_smile_data[i];
    }

    revealed_data[selfrica_max_length] <== ofac_name_dob_circuit.ofacCheckResult * selector_ofac;
    revealed_data[selfrica_max_length + 1] <== ofac_name_yob_circuit.ofacCheckResult * selector_ofac;
    revealed_data[selfrica_max_length + 2] <== older_than_verified[0] * selector_older_than;
    revealed_data[selfrica_max_length + 3] <== older_than_verified[1] * selector_older_than;
    revealed_data[selfrica_max_length + 4] <== older_than_verified[2] * selector_older_than;

    component country_not_in_list_circuit = CountryNotInList(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH, country_length);

    for (var i = 0; i < country_length; i++) {
        country_not_in_list_circuit.country[i] <== smile_data[country_index + i];
    }
    country_not_in_list_circuit.forbidden_countries_list <== forbidden_countries_list;

    var chunkLength = computeIntChunkLength(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH * country_length);
    signal output forbidden_countries_list_packed[chunkLength] <== country_not_in_list_circuit.forbidden_countries_list_packed;

    var revealed_data_packed_chunk_length = computeIntChunkLength(selfrica_max_length + 2 + 3);
    signal output revealedData_packed[revealed_data_packed_chunk_length] <== PackBytes(selfrica_max_length + 2 + 3)(revealed_data);
}
