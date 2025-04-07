#define _DEFAULT_SOURCE 1
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#define _XOPEN_SOURCE 500
#define _STAT_VER 3
#define LDFL_CONFIG "multimapping.h"

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>

#include "ldfl.c" // Include the header containing the generate_header function declaration.

void test_multi_rule_matching(void) {
    // Test path that should match all rules
    const char          *test_path      = "test1";
    compiled_mapping_t **matching_rules = NULL;
    pcre2_match_data   **match_data     = NULL;
    int                  num_rules      = 0;

    // Find matching rules
    bool found = ldfl_find_matching_rules("open", test_path, LDFL_OP_MAP, &matching_rules, &num_rules, &match_data);
    CU_ASSERT_EQUAL(found, true);
    CU_ASSERT_EQUAL(num_rules, 3);

    // Verify the rules
    for (int i = 0; i < num_rules; i++) {
        CU_ASSERT_PTR_NOT_NULL(matching_rules[i]->mapping);
        CU_ASSERT_PTR_NOT_NULL(matching_rules[i]->matching_regex);
    }

    // Cleanup
    for (int i = 0; i < num_rules; i++) {
        pcre2_match_data_free(match_data[i]);
    }
    free(match_data);
    free(matching_rules);
}

int main() {
    CU_initialize_registry();

    // Add the new test suite
    CU_pSuite pSuite = CU_add_suite("Multi Rule Tests", NULL, NULL);
    CU_add_test(pSuite, "test_multi_rule_matching", test_multi_rule_matching);

    // Run the tests using the basic interface
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_get_error();
    int ret = CU_get_number_of_failures();
    CU_cleanup_registry();
    return ret;
}
