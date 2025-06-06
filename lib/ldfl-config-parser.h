/** @cond */
#include <jansson.h>
#include <string.h>
#include <stdlib.h>

// Default  Mapping
ldfl_rule_t default_default[] = {
    {"default noop rule", ".*", LDFL_OP_NOOP, NULL, LDFL_PATH_ABS, false, NULL},
    {NULL, NULL, LDFL_OP_END, NULL, LDFL_PATH_ABS, NULL, NULL} // keep this last value
};

ldfl_rule_t *ldfl_rule = default_default;

ldfl_setting_t ldfl_setting = {
    .log_mask  = LDFL_LOG_INIT,
    .log_level = LOG_INFO,
    .logger    = ldfl_stderr_logger,
};

// Helper function to convert JSON string to operation type
static ldfl_operation_t json_to_operation(const char *op_str) {
    if (strcmp(op_str, "noop") == 0)
        return LDFL_OP_NOOP;
    if (strcmp(op_str, "path_redir") == 0)
        return LDFL_OP_PATH_REDIR;
    if (strcmp(op_str, "exec_redir") == 0)
        return LDFL_OP_EXEC_REDIR;
    if (strcmp(op_str, "mem_open") == 0)
        return LDFL_OP_MEM_OPEN;
    if (strcmp(op_str, "mem_data") == 0)
        return LDFL_OP_MEM_DATA;
    if (strcmp(op_str, "perm") == 0)
        return LDFL_OP_PERM;
    if (strcmp(op_str, "deny") == 0)
        return LDFL_OP_DENY;
    if (strcmp(op_str, "ro") == 0)
        return LDFL_OP_RO;
    return LDFL_OP_END;
}

// Helper function to convert JSON string to path type
static ldfl_path_type_t json_to_path_type(const char *path_type_str) {
    if (strcmp(path_type_str, "absolute") == 0)
        return LDFL_PATH_ABS;
    return LDFL_PATH_ORIG;
}

// Helper function to convert JSON string to log level
static int json_to_log_level(const char *level_str) {
    if (strcmp(level_str, "emerg") == 0)
        return LOG_EMERG;
    if (strcmp(level_str, "alert") == 0)
        return LOG_ALERT;
    if (strcmp(level_str, "crit") == 0)
        return LOG_CRIT;
    if (strcmp(level_str, "err") == 0)
        return LOG_ERR;
    if (strcmp(level_str, "warning") == 0)
        return LOG_WARNING;
    if (strcmp(level_str, "notice") == 0)
        return LOG_NOTICE;
    if (strcmp(level_str, "info") == 0)
        return LOG_INFO;
    if (strcmp(level_str, "debug") == 0)
        return LOG_DEBUG;
    return LOG_DEBUG; // Default to debug
}

// Helper function to convert JSON string to logger function
static ldfl_logger_t json_to_logger(const char *logger_str) {
    if (strcmp(logger_str, "syslog") == 0)
        return ldfl_syslog_logger;
    if (strcmp(logger_str, "stderr") == 0)
        return ldfl_stderr_logger;
    return ldfl_dummy_logger; // Default to dummy logger
}

// Helper function to convert JSON string to log mask
static uint64_t json_to_log_mask(json_t *log_mask_array) {
    uint64_t mask = 0;
    size_t   index;
    json_t  *value;

    json_array_foreach(log_mask_array, index, value) {
        const char *mask_str = json_string_value(value);
        if (strcmp(mask_str, "rule_search") == 0)
            mask |= LDFL_LOG_RULE_SEARCH;
        if (strcmp(mask_str, "rule_apply") == 0)
            mask |= LDFL_LOG_RULE_APPLY;
        if (strcmp(mask_str, "rule_found") == 0)
            mask |= LDFL_LOG_RULE_FOUND;
        if (strcmp(mask_str, "fn_call") == 0)
            mask |= LDFL_LOG_FN_CALL;
        if (strcmp(mask_str, "init") == 0)
            mask |= LDFL_LOG_INIT;
        if (strcmp(mask_str, "fn_call_err") == 0)
            mask |= LDFL_LOG_FN_CALL_ERR;
        if (strcmp(mask_str, "all") == 0)
            mask |= LDFL_LOG_ALL;
    }
    return mask;
}

// Parse JSON configuration file
int ldfl_parse_json_config(const char *config_file) {
    json_error_t error;
    json_t      *root = json_load_file(config_file, 0, &error);
    if (!root) {
        fprintf(stderr, "Error parsing JSON config '%s': %s (line %d, column %d)\n", config_file, error.text, error.line, error.column);
        return -1;
    }

    // Parse settings
    json_t *settings = json_object_get(root, "settings");
    if (settings) {
        json_t *log_mask = json_object_get(settings, "log_mask");
        if (log_mask && json_is_array(log_mask)) {
            ldfl_setting.log_mask = json_to_log_mask(log_mask);
        }

        json_t *log_level = json_object_get(settings, "log_level");
        if (log_level && json_is_string(log_level)) {
            ldfl_setting.log_level = json_to_log_level(json_string_value(log_level));
        }

        json_t *logger = json_object_get(settings, "logger");
        if (logger && json_is_string(logger)) {
            ldfl_setting.logger = json_to_logger(json_string_value(logger));
        }
    }

    // Parse rules
    json_t *rules = json_object_get(root, "rules");
    if (rules && json_is_array(rules)) {
        size_t rule_count = json_array_size(rules);
        ldfl_rule         = calloc(rule_count + 1, sizeof(ldfl_rule_t)); // +1 for sentinel

        size_t  index;
        json_t *rule;
        json_array_foreach(rules, index, rule) {
            json_t *name           = json_object_get(rule, "name");
            json_t *search_pattern = json_object_get(rule, "search_pattern");
            json_t *operation      = json_object_get(rule, "operation");
            json_t *target         = json_object_get(rule, "target");
            json_t *path_transform = json_object_get(rule, "path_transform");
            json_t *extra_options  = json_object_get(rule, "extra_options");
            json_t *final          = json_object_get(rule, "final");

            if (name && search_pattern && operation) {
                ldfl_rule[index].name           = strdup(json_string_value(name));
                ldfl_rule[index].search_pattern = strdup(json_string_value(search_pattern));
                ldfl_rule[index].operation      = json_to_operation(json_string_value(operation));

                if (target && !json_is_null(target)) {
                    ldfl_rule[index].target = strdup(json_string_value(target));
                } else {
                    ldfl_rule[index].target = NULL;
                }

                if (path_transform) {
                    ldfl_rule[index].path_transform = json_to_path_type(json_string_value(path_transform));
                } else {
                    ldfl_rule[index].path_transform = LDFL_PATH_ABS;
                }

                if (extra_options && !json_is_null(extra_options)) {
                    ldfl_rule[index].extra_options = strdup(json_string_value(extra_options));
                } else {
                    ldfl_rule[index].extra_options = NULL;
                }

                if (final && json_is_boolean(final)) {
                    ldfl_rule[index].final = json_boolean_value(final);
                } else {
                    ldfl_rule[index].final = false; // Default to false if not specified
                }
            }
        }

        // Add sentinel entry
        ldfl_rule[rule_count].name           = NULL;
        ldfl_rule[rule_count].search_pattern = NULL;
        ldfl_rule[rule_count].operation      = LDFL_OP_END;
        ldfl_rule[rule_count].target         = NULL;
        ldfl_rule[rule_count].path_transform = LDFL_PATH_ABS;
        ldfl_rule[rule_count].extra_options  = NULL;
        ldfl_rule[rule_count].final          = false;
    }

    json_decref(root);
    return 0;
}

// Free allocated memory from JSON config
void ldfl_free_json_config(void) {
    if (ldfl_rule && ldfl_rule != default_default) {
        for (int i = 0; ldfl_rule[i].operation != LDFL_OP_END; i++) {
            free((void *)ldfl_rule[i].name);
            free((void *)ldfl_rule[i].search_pattern);
            free((void *)ldfl_rule[i].target);
            free((void *)ldfl_rule[i].extra_options);
        }
        free(ldfl_rule);
        ldfl_rule = NULL;
    }
}
/** @endcond */
