#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#define LDLF_UTILS_TESTING

#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <jansson.h>

#include "../lib/ldfl.c"

// Test fixture setup and teardown
static int setup(void) {
    return 0;
}

static int teardown(void) {
    return 0;
}

// Test cases
void test_json_to_operation(void) {
    CU_ASSERT_EQUAL(json_to_operation("noop"), LDFL_OP_NOOP);
    CU_ASSERT_EQUAL(json_to_operation("map"), LDFL_OP_PATH_REDIR);
    CU_ASSERT_EQUAL(json_to_operation("exec_map"), LDFL_OP_EXEC_REDIR);
    CU_ASSERT_EQUAL(json_to_operation("mem_open"), LDFL_OP_MEM_OPEN);
    CU_ASSERT_EQUAL(json_to_operation("static"), LDFL_OP_MEM_DATA);
    CU_ASSERT_EQUAL(json_to_operation("perm"), LDFL_OP_PERM);
    CU_ASSERT_EQUAL(json_to_operation("deny"), LDFL_OP_DENY);
    CU_ASSERT_EQUAL(json_to_operation("ro"), LDFL_OP_RO);
    CU_ASSERT_EQUAL(json_to_operation("invalid"), LDFL_OP_END);
}

void test_json_to_path_type(void) {
    CU_ASSERT_EQUAL(json_to_path_type("absolute"), LDFL_PATH_ABS);
    CU_ASSERT_EQUAL(json_to_path_type("original"), LDFL_PATH_ORIG);
    CU_ASSERT_EQUAL(json_to_path_type("invalid"), LDFL_PATH_ORIG);
}

void test_json_to_log_level(void) {
    CU_ASSERT_EQUAL(json_to_log_level("emerg"), LOG_EMERG);
    CU_ASSERT_EQUAL(json_to_log_level("alert"), LOG_ALERT);
    CU_ASSERT_EQUAL(json_to_log_level("crit"), LOG_CRIT);
    CU_ASSERT_EQUAL(json_to_log_level("err"), LOG_ERR);
    CU_ASSERT_EQUAL(json_to_log_level("warning"), LOG_WARNING);
    CU_ASSERT_EQUAL(json_to_log_level("notice"), LOG_NOTICE);
    CU_ASSERT_EQUAL(json_to_log_level("info"), LOG_INFO);
    CU_ASSERT_EQUAL(json_to_log_level("debug"), LOG_DEBUG);
    CU_ASSERT_EQUAL(json_to_log_level("invalid"), LOG_DEBUG);
}

void test_json_to_logger(void) {
    CU_ASSERT_EQUAL(json_to_logger("syslog"), ldfl_syslog_logger);
    CU_ASSERT_EQUAL(json_to_logger("stderr"), ldfl_stderr_logger);
    CU_ASSERT_EQUAL(json_to_logger("invalid"), ldfl_dummy_logger);
}

void test_json_to_log_mask(void) {
    json_t *mask_array = json_array();
    json_array_append_new(mask_array, json_string("mapping_rule_found"));
    json_array_append_new(mask_array, json_string("fn_call"));

    uint64_t mask = json_to_log_mask(mask_array);
    CU_ASSERT(mask & LDFL_LOG_RULE_FOUND);
    CU_ASSERT(mask & LDFL_LOG_FN_CALL);
    CU_ASSERT_FALSE(mask & LDFL_LOG_INIT);

    json_decref(mask_array);
}

void test_parse_valid_config(void) {
    const char *test_config = "{\n"
                              "  \"settings\": {\n"
                              "    \"log_mask\": [\"mapping_rule_found\", \"fn_call\"],\n"
                              "    \"log_level\": \"debug\",\n"
                              "    \"logger\": \"stderr\"\n"
                              "  },\n"
                              "  \"mappings\": [\n"
                              "    {\n"
                              "      \"name\": \"test_mapping\",\n"
                              "      \"search_pattern\": \"test.*\",\n"
                              "      \"operation\": \"map\",\n"
                              "      \"target\": \"/test/target\",\n"
                              "      \"path_transform\": \"absolute\"\n"
                              "    }\n"
                              "  ]\n"
                              "}";

    FILE *fp = fopen("test_config.json", "w");
    CU_ASSERT_PTR_NOT_NULL_FATAL(fp);
    fprintf(fp, "%s", test_config);
    fclose(fp);

    int result = ldfl_parse_json_config("test_config.json");
    CU_ASSERT_EQUAL(result, 0);

    // Verify settings
    CU_ASSERT(ldfl_setting.log_mask & LDFL_LOG_RULE_FOUND);
    CU_ASSERT(ldfl_setting.log_mask & LDFL_LOG_FN_CALL);
    CU_ASSERT_EQUAL(ldfl_setting.log_level, LOG_DEBUG);
    CU_ASSERT_EQUAL(ldfl_setting.logger, ldfl_stderr_logger);

    // Verify mappings
    CU_ASSERT_PTR_NOT_NULL(ldfl_mapping);
    CU_ASSERT_STRING_EQUAL(ldfl_mapping[0].name, "test_mapping");
    CU_ASSERT_STRING_EQUAL(ldfl_mapping[0].search_pattern, "test.*");
    CU_ASSERT_EQUAL(ldfl_mapping[0].operation, LDFL_OP_PATH_REDIR);
    CU_ASSERT_STRING_EQUAL(ldfl_mapping[0].target, "/test/target");
    CU_ASSERT_EQUAL(ldfl_mapping[0].path_transform, LDFL_PATH_ABS);

    remove("test_config.json");
}

void test_parse_invalid_config(void) {
    const char *invalid_config = "{\n"
                                 "  \"settings\": {\n"
                                 "    \"log_mask\": [\"invalid_mask\"],\n"
                                 "    \"log_level\": \"invalid_level\",\n"
                                 "    \"logger\": \"invalid_logger\"\n"
                                 "  }\n"
                                 "}";

    FILE *fp = fopen("invalid_config.json", "w");
    CU_ASSERT_PTR_NOT_NULL_FATAL(fp);
    fprintf(fp, "%s", invalid_config);
    fclose(fp);

    int result = ldfl_parse_json_config("invalid_config.json");
    CU_ASSERT_EQUAL(result, 0); // Should still parse successfully

    // Verify default values for invalid settings
    CU_ASSERT_EQUAL(ldfl_setting.log_level, LOG_DEBUG);
    CU_ASSERT_EQUAL(ldfl_setting.logger, ldfl_dummy_logger);

    remove("invalid_config.json");
}

void test_parse_missing_config(void) {
    int result = ldfl_parse_json_config("nonexistent.json");
    CU_ASSERT_EQUAL(result, -1);
}

int main() {
    CU_pSuite pSuite = NULL;

    if (CUE_SUCCESS != CU_initialize_registry())
        return CU_get_error();

    pSuite = CU_add_suite("JSON Config Test Suite", setup, teardown);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    if ((NULL == CU_add_test(pSuite, "test_json_to_operation", test_json_to_operation)) ||
        (NULL == CU_add_test(pSuite, "test_json_to_path_type", test_json_to_path_type)) ||
        (NULL == CU_add_test(pSuite, "test_json_to_log_level", test_json_to_log_level)) ||
        (NULL == CU_add_test(pSuite, "test_json_to_logger", test_json_to_logger)) ||
        (NULL == CU_add_test(pSuite, "test_json_to_log_mask", test_json_to_log_mask)) ||
        (NULL == CU_add_test(pSuite, "test_parse_valid_config", test_parse_valid_config)) ||
        (NULL == CU_add_test(pSuite, "test_parse_invalid_config", test_parse_invalid_config)) ||
        (NULL == CU_add_test(pSuite, "test_parse_missing_config", test_parse_missing_config))) {
        CU_cleanup_registry();
        return CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    return CU_get_error();
}
