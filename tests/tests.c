#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fliar-priv.h" // Include the header containing the generate_header function declaration.

void test_generate_header() {
    const char *input_file = "test_input.bin";
    const char *output_file = "test_output.h";
    const char *var_name = "test_var";

    // Create a test binary file
    FILE *in = fopen(input_file, "wb");
    CU_ASSERT_PTR_NOT_NULL_FATAL(in);

    unsigned char test_data[] = {0xDE, 0xAD, 0xBE, 0xEF};
    fwrite(test_data, sizeof(unsigned char), sizeof(test_data), in);
    fclose(in);

    // Generate the header file
    generate_header(input_file, output_file, var_name);

    // Validate the generated header file
    FILE *out = fopen(output_file, "r");
    CU_ASSERT_PTR_NOT_NULL_FATAL(out);

    char buffer[256];
    int contains_variable = 0;
    while (fgets(buffer, sizeof(buffer), out)) {
        if (strstr(buffer, "const unsigned char test_var[4] = {")) {
            contains_variable = 1;
            break;
        }
    }
    fclose(out);

    CU_ASSERT(contains_variable);

    // Cleanup
    remove(input_file);
    remove(output_file);
}

int main() {
    // Initialize CUnit test registry
    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    CU_pSuite suite = CU_add_suite("generate_header_test_suite", NULL, NULL);
    if (!suite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Add the test to the suite
    if (!CU_add_test(suite, "test_generate_header", test_generate_header)) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    // Run the tests using the basic interface
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();

    return CU_get_error();
}
