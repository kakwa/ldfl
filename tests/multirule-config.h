ldfl_rule_t ldfl_rule[] = {
    {"rule1", "test(.)",     LDFL_OP_PATH_REDIR, "test1_rule", LDFL_PATH_ABS, false, NULL},
    {"rule2", "test(1)",     LDFL_OP_NOOP,       "test2_rule", LDFL_PATH_ABS, false, NULL},
    {"rule3", "test([0-9])", LDFL_OP_RO,         "test3_rule", LDFL_PATH_ABS, false, NULL},
    {"rule4", "tes.(.)",     LDFL_OP_PATH_REDIR, "test4_rule", LDFL_PATH_ABS, false, NULL},
    {NULL, NULL,             LDFL_OP_END,        NULL,         LDFL_PATH_ABS, false, NULL},
};

ldfl_setting_t ldfl_setting = {
    .log_mask = LDFL_LOG_RULE_FOUND | LDFL_LOG_FN_CALL | LDFL_LOG_INIT | LDFL_LOG_RULE_APPLY |
                LDFL_LOG_FN_CALL_ERR | LDFL_LOG_RULE_SEARCH,
    .log_level = LOG_DEBUG,
    .logger    = ldfl_stderr_logger,
};
