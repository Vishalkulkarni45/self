include "./ofac/ofac_name_dob_selfrica.circom";
include "./ofac/ofac_name_yob_selfrica.circom";
include "./country_not_in_list.circom";
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

    signal input forbidden_countries_list[MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH];

    signal input ofac_name_dob_smt_leaf_key;
    signal input ofac_name_dob_smt_root;
    signal input ofac_name_dob_smt_siblings[name_dob_tree_levels];

    signal input ofac_name_yob_smt_leaf_key;
    signal input ofac_name_yob_smt_root;
    signal input ofac_name_yob_smt_siblings[name_yob_tree_levels];

    signal input selector_ofac;
    selector_ofac * (selector_ofac - 1) === 0;

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

    signal revealed_data[selfrica_max_length + 2];
    for (var i = 0; i < selfrica_max_length; i++) {
        revealed_data[i] <== smile_data[i] * selector_smile_data[i];
    }

    revealed_data[selfrica_max_length] <== ofac_name_dob_circuit.ofacCheckResult;
    revealed_data[selfrica_max_length + 1] <== ofac_name_yob_circuit.ofacCheckResult;

    component country_not_in_list_circuit = CountryNotInList(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH);
    for (var i = 0; i < country_length; i++) { 
        country_not_in_list_circuit.country[i] <== smile_data[i];
    }
    country_not_in_list_circuit.forbidden_countries_list <== forbidden_countries_list;

    var chunkLength = computeIntChunkLength(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH * 2);
    signal country[country_length] = [smile_data[country_index], smile_data[country_index + 1]];
    signal output forbidden_countries_list_packed[chunkLength] <== CountryNotInList(MAX_FORBIDDEN_COUNTRIES_LIST_LENGTH)(country, forbidden_countries_list);
}